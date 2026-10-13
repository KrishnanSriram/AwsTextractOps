#!/usr/bin/env bash
# Submit three documents as each team, wait, then fetch every result once.
# Usage: API=https://xxxx.execute-api.us-east-2.amazonaws.com ./run_chargeback_test.sh
set -euo pipefail
: "${API:?Set API to your API Gateway invoke URL}"

files_for() {   # macOS ships bash 3.2, which has no associative arrays
  case "$1" in
    team-alpha) echo "textract_sample.pdf customer_record_pii.pdf shipping_order_2page.pdf" ;;
    team-beta)  echo "shipping_order_2page.pdf quarterly_report_5page.pdf textract_sample.pdf" ;;
    team-gamma) echo "quarterly_report_5page.pdf quarterly_report_5page.pdf customer_record_pii.pdf" ;;
  esac
}

sign() {   # print curl signing options for a profile
  eval "$(aws configure export-credentials --profile "$1" --format env)"
  SIGN=(--aws-sigv4 "aws:amz:us-east-2:execute-api"
        --user "$AWS_ACCESS_KEY_ID:$AWS_SECRET_ACCESS_KEY"
        -H "x-amz-security-token: $AWS_SESSION_TOKEN")
}

: > jobs.txt
for profile in team-alpha team-beta team-gamma; do
  sign "$profile"
  for f in $(files_for "$profile"); do
    printf '{"filename":"%s","content_base64":"%s"}' "$f" "$(base64 < "$f" | tr -d '\n')" > /tmp/body.json
    out=$(curl -s -X POST "$API/documents" "${SIGN[@]}" -H 'Content-Type: application/json' -d @/tmp/body.json)
    echo "$profile  $f  $out"
    job=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["document_id"])' <<<"$out")
    echo "$profile $job" >> jobs.txt
  done
done

echo "Waiting 30 seconds for Textract..."; sleep 30

while read -r profile job; do
  sign "$profile"
  for attempt in 1 2 3 4 5 6; do
    status=$(curl -s "$API/documents/$job" "${SIGN[@]}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("status"))')
    [ "$status" != "IN_PROGRESS" ] && break
    sleep 5
  done
  echo "$profile  ${job:0:12}...  $status"
done < jobs.txt
