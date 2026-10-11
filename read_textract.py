import sys
import boto3

textract = boto3.client("textract")
job_id = sys.argv[1]

# Collect every block, following NextToken for long documents
blocks, token = [], None
while True:
    args = {"JobId": job_id, **({"NextToken": token} if token else {})}
    page = textract.get_document_analysis(**args)
    if page["JobStatus"] != "SUCCEEDED":
        sys.exit(f"Job status: {page['JobStatus']} {page.get('StatusMessage', '')}")
    blocks += page["Blocks"]
    token = page.get("NextToken")
    if not token:
        break

by_id = {b["Id"]: b for b in blocks}

def linked(block, kind):
    return [i for r in block.get("Relationships", []) if r["Type"] == kind for i in r["Ids"]]

def text_of(block):
    words = []
    for child in (by_id[i] for i in linked(block, "CHILD")):
        if child["BlockType"] == "WORD":
            words.append(child["Text"])
        elif child["BlockType"] == "SELECTION_ELEMENT":
            words.append("[x]" if child["SelectionStatus"] == "SELECTED" else "[ ]")
    return " ".join(words)

print("FORMS")
for b in blocks:
    if b["BlockType"] == "KEY_VALUE_SET" and "KEY" in b.get("EntityTypes", []):
        value = " ".join(text_of(by_id[i]) for i in linked(b, "VALUE"))
        print(f"  {text_of(b)} -> {value}")

for n, table in enumerate((b for b in blocks if b["BlockType"] == "TABLE"), 1):
    print(f"\nTABLE {n} (page {table.get('Page', 1)})")
    cells = [by_id[i] for i in linked(table, "CHILD") if by_id[i]["BlockType"] == "CELL"]
    rows = {}
    for c in cells:
        rows.setdefault(c["RowIndex"], {})[c["ColumnIndex"]] = text_of(c)
    for r in sorted(rows):
        print("  " + " | ".join(rows[r][c] for c in sorted(rows[r])))