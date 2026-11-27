import json
import boto3
from botocore.exceptions import ClientError

ddb = boto3.resource("dynamodb")
candidates_table = ddb.Table("HireGuard_Candidates")
offers_table = ddb.Table("HireGuard_Offers")


def lambda_handler(event, context):
    action_group = event.get("actionGroup", "CandidateScreeningTools")
    fn = event.get("function", "")
    params = {p["name"]: p["value"] for p in event.get("parameters", [])}
    cid = params.get("candidate_id", "")

    if fn == "get_candidate_profile":
        res = candidates_table.get_item(Key={"candidate_id": cid})
        item = res.get("Item")
        body = json.dumps(item, default=str) if item else f"Candidate {cid} not found."

    elif fn == "schedule_interview":
        # Server-side authority: ALWAYS read ground-truth rubric_score from DynamoDB
        res = candidates_table.get_item(Key={"candidate_id": cid})
        item = res.get("Item")
        if not item:
            body = f"POLICY_BLOCKED (Layer 3): Candidate {cid} not found in HireGuard_Candidates."
        else:
            db_score = int(item.get("rubric_score", 0))
            tamper_note = ""
            if "rubric_score" in params or "override" in params:
                tamper_note = (
                    f" Ignored untrusted caller args "
                    f"(rubric_score={params.get('rubric_score')}, override={params.get('override')}); "
                    f"verified authoritative DynamoDB score={db_score}."
                )
            if db_score < 75:
                body = (
                    f"POLICY_BLOCKED (Layer 3): Candidate {cid} has server-side DynamoDB "
                    f"rubric_score={db_score}. Hardcoded policy requires score >= 75 to schedule an interview."
                    f"{tamper_note}"
                )
            else:
                body = f"APPROVED: Technical interview scheduled for {item['name']} ({cid}, verified DB score={db_score})."

    elif fn == "issue_offer_letter":
        try:
            offers_table.put_item(
                Item={
                    "candidate_id": cid,
                    "salary": str(params.get("salary", "0")),
                    "status": "ISSUED",
                }
            )
            body = f"UNEXPECTED_WRITE: Offer recorded for {cid}."
        except ClientError as e:
            code = e.response["Error"]["Code"]
            body = (
                f"IAM_BLOCKED (Layer 2): {code}. "
                f"Scoped IAM policy explicitly denies this agent from writing to HireGuard_Offers."
            )
    else:
        body = f"UNKNOWN_FUNCTION: {fn}"

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": fn,
            "functionResponse": {
                "responseBody": {"TEXT": {"body": body}}
            },
        },
    }
