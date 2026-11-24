import json
import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb", region_name="ap-southeast-2")
CANDIDATES_TABLE = dynamodb.Table("HireGuard_Candidates")
OFFERS_TABLE = dynamodb.Table("HireGuard_Offers")

def lambda_handler(event, context):
    action_group = event["actionGroup"]
    function = event["function"]
    params = {p["name"]: p["value"] for p in event.get("parameters", [])}

    if function == "get_candidate_profile":
        cid = params.get("candidate_id", "")
        resp = CANDIDATES_TABLE.get_item(Key={"candidate_id": cid})
        item = resp.get("Item")
        result = json.dumps(item, default=str) if item else f"Candidate {cid} not found."

    elif function == "schedule_interview":
        cid = params.get("candidate_id", "")
        resp = CANDIDATES_TABLE.get_item(Key={"candidate_id": cid})
        item = resp.get("Item")
        if not item:
            result = f"DENIED: Candidate {cid} does not exist."
        elif int(item.get("rubric_score", 0)) < 75:
            # LAYER 3: Deterministic Policy Gate (cannot be bypassed by prompts)
            result = (
                f"POLICY_BLOCKED (Layer 3): Candidate {cid} has rubric_score={item['rubric_score']}. "
                f"Hardcoded policy requires score >= 75 to schedule an interview."
            )
        else:
            result = f"APPROVED: Technical interview scheduled for {item['name']} ({cid})."

    elif function == "issue_offer_letter":
        cid = params.get("candidate_id", "")
        salary = params.get("salary", "0")
        try:
            # LAYER 2: Scoped IAM Policy explicitly DENIES writes to HireGuard_Offers
            OFFERS_TABLE.put_item(Item={"candidate_id": cid, "salary": str(salary), "status": "ISSUED"})
            result = f"Offer issued to {cid}."
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                result = (
                    "IAM_BLOCKED (Layer 2): AccessDeniedException. "
                    "Scoped IAM policy explicitly denies this agent from writing to HireGuard_Offers."
                )
            else:
                result = f"Error: {str(e)}"
    else:
        result = f"Unknown function: {function}"

    return {
        "messageVersion": "1.0",
        "response": {
            "actionGroup": action_group,
            "function": function,
            "functionResponse": {
                "responseBody": {"TEXT": {"body": result}}
            },
        },
    }
