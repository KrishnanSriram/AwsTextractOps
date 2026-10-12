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
            return get(event["job_id"])
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
            result = get(event["pathParameters"]["job_id"])
            return reply(202 if result["status"] == "IN_PROGRESS" else 200, result)
    except (ClientError, ValueError) as exc:
        return reply(400, {"error": str(exc)})

    return reply(404, {"error": "Not found"})