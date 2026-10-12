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
comprehend = boto3.client("comprehend")

PII_MODES = ("redact", "detect", "block", "off")
MIN_SCORE = 0.5                      # act on anything Comprehend is at least 50% sure of
CARD_TYPES = {"CREDIT_DEBIT_NUMBER", "CREDIT_DEBIT_CVV"}

# Optional second check for card numbers that Comprehend did not flag:
# 13 to 19 digit runs that pass the Luhn checksum. Set to False to rely on Comprehend alone.
USE_LUHN_BACKUP = True
CARD_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


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


# ---------- PII and card-data scanning (Amazon Comprehend) ----------

def luhn_ok(digits):
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def find_sensitive(text):
    """Return non-overlapping (start, end, type) spans of sensitive data in text."""
    spans = []
    if text.strip():
        found = comprehend.detect_pii_entities(Text=text, LanguageCode="en")["Entities"]
        spans = [(e["BeginOffset"], e["EndOffset"], e["Type"])
                 for e in found if e["Score"] >= MIN_SCORE]
    if USE_LUHN_BACKUP:
        for m in CARD_PATTERN.finditer(text):
            digits = re.sub(r"\D", "", m.group())
            overlaps = any(m.start() < end and start < m.end() for start, end, _ in spans)
            if luhn_ok(digits) and not overlaps:
                spans.append((m.start(), m.end(), "CREDIT_DEBIT_NUMBER"))
    return sorted(spans)


def scan(pages, mode):
    """Scan each page. Returns (pages, counts of each type found, blocked)."""
    counts, cleaned = {}, {}
    for number, lines in pages.items():
        text = "\n".join(lines)
        spans = find_sensitive(text)
        for _, _, kind in spans:
            counts[kind] = counts.get(kind, 0) + 1
        if mode == "redact":
            for start, end, kind in reversed(spans):
                text = text[:start] + f"[{kind}]" + text[end:]
        cleaned[number] = text.split("\n")
    return cleaned, counts, False


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