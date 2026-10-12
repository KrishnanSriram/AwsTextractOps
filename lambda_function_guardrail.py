import base64
import json
import os
import re
import uuid

import boto3
from botocore.exceptions import ClientError

BUCKET = os.environ["BUCKET"]
s3 = boto3.client("s3")
textract = boto3.client("textract")
bedrock = boto3.client("bedrock-runtime")

GUARDRAIL_ID = os.environ["GUARDRAIL_ID"]
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

PII_MODES = ("redact", "detect", "block", "off")
CARD_TYPES = {"CREDIT_DEBIT_CARD_NUMBER", "CREDIT_DEBIT_CARD_CVV"}
MAX_CHARS = 10000                    # text sent to the guardrail per call


def upload(filename, content_base64):
    data = base64.b64decode(content_base64, validate=True)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(filename or "document"))
    key = f"uploads/{uuid.uuid4().hex}-{name}"
    s3.put_object(Bucket=BUCKET, Key=key, Body=data)
    return key


def start(key):
    out = textract.start_document_text_detection(
        DocumentLocation={"S3Object": {"Bucket": BUCKET, "Name": key}}
    )
    return {"job_id": out["JobId"], "status": "IN_PROGRESS", "key": key}


def get(job_id):
    pages, token = {}, None
    while True:
        args = {"JobId": job_id}
        if token:
            args["NextToken"] = token
        out = textract.get_document_text_detection(**args)
        if out["JobStatus"] != "SUCCEEDED":
            return {"job_id": job_id, "status": out["JobStatus"],
                    "message": out.get("StatusMessage", "")}
        for block in out["Blocks"]:
            if block["BlockType"] == "LINE":
                pages.setdefault(str(block.get("Page", 1)), []).append(block["Text"])
        token = out.get("NextToken")
        if not token:
            return {"job_id": job_id, "status": "SUCCEEDED", "pages": pages}


# ---------- PII and card-data scanning (Amazon Bedrock Guardrails) ----------

def chunks(lines):
    """Group a page's lines into pieces of at most MAX_CHARS characters."""
    piece, size = [], 0
    for line in lines:
        if piece and size + len(line) + 1 > MAX_CHARS:
            yield piece
            piece, size = [], 0
        piece.append(line)
        size += len(line) + 1
    if piece:
        yield piece


def guard(lines):
    """Run the guardrail on some lines. Returns (masked lines, matches, blocked)."""
    text = "\n".join(lines)
    if not text.strip():
        return lines, [], False
    out = bedrock.apply_guardrail(
        guardrailIdentifier=GUARDRAIL_ID,
        guardrailVersion=GUARDRAIL_VERSION,
        source="OUTPUT",
        content=[{"text": {"text": text}}],
    )
    matches = []
    for assessment in out.get("assessments", []):
        policy = assessment.get("sensitiveInformationPolicy", {})
        for entity in policy.get("piiEntities", []):
            if entity.get("action") != "NONE":
                matches.append((entity["type"], entity["action"]))
        for regex in policy.get("regexes", []):
            if regex.get("action") != "NONE":
                matches.append((regex["name"], regex["action"]))
    blocked = any(action == "BLOCKED" for _, action in matches)
    if out["action"] == "GUARDRAIL_INTERVENED" and not blocked:
        lines = "".join(o["text"] for o in out["outputs"]).split("\n")
    return lines, matches, blocked


def scan(pages, mode):
    """Scan each page. Returns (pages, counts of each type found, blocked)."""
    counts, cleaned, blocked = {}, {}, False
    for number, lines in pages.items():
        masked = []
        for piece in chunks(lines):
            piece_masked, matches, piece_blocked = guard(piece)
            masked.extend(piece_masked)
            blocked = blocked or piece_blocked
            for kind, _ in matches:
                counts[kind] = counts.get(kind, 0) + 1
        cleaned[number] = masked if mode == "redact" else lines
    return cleaned, counts, blocked


def apply_pii_mode(result, mode):
    """Return (HTTP status, body) for a finished job, after applying the pii setting."""
    if mode == "off" or result["status"] != "SUCCEEDED":
        return 200, result
    pages, counts, blocked = scan(result["pages"], mode)
    result["pii"] = {"mode": mode, "found": counts}
    if blocked or (mode == "block" and CARD_TYPES & set(counts)):
        del result["pages"]
        result["status"] = "BLOCKED"
        result["message"] = "Card data was found, so the text is withheld."
        return 422, result
    result["pages"] = pages
    return 200, result


def reply(status_code, body):
    return {"statusCode": status_code,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body)}


def lambda_handler(event, context):
    route = event.get("routeKey")

    if route is None:  # console Test events
        if "key" in event:
            return start(event["key"])
        if "job_id" in event:
            return apply_pii_mode(get(event["job_id"]), event.get("pii", "redact"))[1]
        return {"error": 'Send {"key": "..."} or {"job_id": "..."}'}

    try:
        if route == "POST /documents":
            raw = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw)
            body = json.loads(raw)
            if body.get("content_base64"):
                key = upload(body.get("filename"), body["content_base64"])
            else:
                key = body.get("key")
            if not key:
                return reply(400, {"error": 'Send {"key": ...} or {"filename": ..., "content_base64": ...}'})
            return reply(202, start(key))

        if route == "GET /documents/{job_id}":
            mode = (event.get("queryStringParameters") or {}).get("pii", "redact")
            if mode not in PII_MODES:
                return reply(400, {"error": f"pii must be one of: {', '.join(PII_MODES)}"})
            result = get(event["pathParameters"]["job_id"])
            if result["status"] == "IN_PROGRESS":
                return reply(202, result)
            return reply(*apply_pii_mode(result, mode))
    except (ClientError, ValueError) as exc:
        return reply(400, {"error": str(exc)})

    return reply(404, {"error": "Not found"})