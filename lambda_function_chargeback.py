import base64
import hashlib
import hmac
import json
import os
import re
import time
import uuid

import boto3
from botocore.exceptions import ClientError

BUCKET = os.environ["BUCKET"]
s3 = boto3.client("s3")
textract = boto3.client("textract")
bedrock = boto3.client("bedrock-runtime")
TEAM_ROLES = json.loads(os.environ.get("TEAM_ROLES", "{}"))
DOC_ID_SECRET = os.environ["DOC_ID_SECRET"].encode()
if len(DOC_ID_SECRET) < 32:
    raise RuntimeError("DOC_ID_SECRET must be at least 32 characters")

GUARDRAIL_ID = os.environ["GUARDRAIL_ID"]
GUARDRAIL_VERSION = os.environ.get("GUARDRAIL_VERSION", "DRAFT")

PII_MODES = ("redact", "detect", "block", "off")
CARD_TYPES = {"CREDIT_DEBIT_CARD_NUMBER", "CREDIT_DEBIT_CARD_CVV"}
MAX_CHARS = 10000                    # text sent to the guardrail per call
TEXT_UNITS = [0]                     # guardrail text units used by the current request


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
    pages, token, page_count = {}, None, 0
    while True:
        args = {"JobId": job_id}
        if token:
            args["NextToken"] = token
        out = textract.get_document_text_detection(**args)
        if out["JobStatus"] != "SUCCEEDED":
            return {"job_id": job_id, "status": out["JobStatus"],
                    "message": out.get("StatusMessage", "")}
        page_count = out.get("DocumentMetadata", {}).get("Pages", page_count)
        for block in out["Blocks"]:
            if block["BlockType"] == "LINE":
                pages.setdefault(str(block.get("Page", 1)), []).append(block["Text"])
        token = out.get("NextToken")
        if not token:
            return {"job_id": job_id, "status": "SUCCEEDED",
                    "page_count": page_count or len(pages), "pages": pages}


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
    TEXT_UNITS[0] += -(-len(text) // 1000)   # billed per 1,000 characters, rounded up
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


# ---------- who is calling, and usage logging ----------

def caller(event):
    """Return (team, caller ARN) from the IAM identity API Gateway verified."""
    arn = (event.get("requestContext", {}).get("authorizer", {})
           .get("iam", {}).get("userArn") or "")
    # arn:aws:sts::<account>:assumed-role/<role name>/<session name>
    role = arn.split("/")[1] if ":assumed-role/" in arn else ""
    return TEAM_ROLES.get(role), arn


def signature(job_id, team):
    mac = hmac.new(DOC_ID_SECRET, f"{job_id}.{team}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(mac).decode().rstrip("=")[:32]


def make_doc_id(job_id, team):
    return f"{job_id}.{team}.{signature(job_id, team)}"


def parse_doc_id(doc_id):
    """Return (job_id, team) if the id is genuine, else None."""
    parts = doc_id.split(".")
    if len(parts) != 3:
        return None
    job_id, team, sig = parts
    if not hmac.compare_digest(sig, signature(job_id, team)):
        return None
    return job_id, team


def log_usage(event_name, team, metrics, **fields):
    """One JSON line in CloudWatch Logs, also published as metrics with a Team dimension."""
    line = {"usage_event": event_name, "team": team, **fields, **metrics}
    if metrics:
        line["_aws"] = {"Timestamp": int(time.time() * 1000), "CloudWatchMetrics": [{
            "Namespace": "TextractAPI", "Dimensions": [["team"]],
            "Metrics": [{"Name": name, "Unit": "Count"} for name in metrics]}]}
    print(json.dumps(line))


def reply(status_code, body):
    return {"statusCode": status_code,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps(body)}


def lambda_handler(event, context):
    route = event.get("routeKey")
    team, arn = caller(event)
    if not team:
        return reply(403, {"error": "Your IAM role is not registered with this service"})

    try:
        if route == "POST /documents":
            raw = event.get("body") or "{}"
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw)
            body = json.loads(raw)
            if not body.get("content_base64"):
                return reply(400, {"error": 'Send {"filename": ..., "content_base64": ...}'})
            key = upload(body.get("filename"), body["content_base64"])
            job = start(key)
            doc_id = make_doc_id(job["job_id"], team)
            log_usage("submit", team, {"Documents": 1}, job_id=job["job_id"],
                      file=os.path.basename(key), caller=arn)
            return reply(202, {"document_id": doc_id, "status": "IN_PROGRESS", "team": team})

        if route == "GET /documents/{job_id}":
            mode = (event.get("queryStringParameters") or {}).get("pii", "redact")
            if mode not in PII_MODES:
                return reply(400, {"error": f"pii must be one of: {', '.join(PII_MODES)}"})
            parsed = parse_doc_id(event["pathParameters"]["job_id"])
            if not parsed or parsed[1] != team:
                return reply(404, {"error": "No such document for your team"})
            job_id = parsed[0]
            result = get(job_id)
            result["document_id"] = event["pathParameters"]["job_id"]
            result.pop("job_id", None)
            if result["status"] == "IN_PROGRESS":
                return reply(202, result)

            TEXT_UNITS[0] = 0
            status, body = apply_pii_mode(result, mode)
            log_usage("fetch", team, {"GuardrailTextUnits": TEXT_UNITS[0]},
                      job_id=job_id, caller=arn, status=result["status"],
                      pages=result.get("page_count", 0), pii_mode=mode)
            return reply(status, body)
    except (ClientError, ValueError) as exc:
        return reply(400, {"error": str(exc)})

    return reply(404, {"error": "Not found"})
