import json, os, time, uuid, boto3
from botocore.config import Config
from botocore.exceptions import ClientError

api_key = os.environ.get("GROQ_API_KEY", "").strip()
if not api_key or "PASTE_YOUR" in api_key:
    raise SystemExit("ERROR: Replace PASTE_YOUR_GSK_KEY_HERE with your gsk_... key first!")

cfg = json.load(open("config.json"))
REGION = cfg["region"]
ctrl = boto3.client("bedrock-agentcore-control", region_name=REGION)
rt = boto3.client("bedrock-agentcore", region_name=REGION, config=Config(read_timeout=30, connect_timeout=10, retries={"max_attempts": 1}))

provider_name = "HireGuardGroqKey"
try:
    cred = ctrl.create_api_key_credential_provider(name=provider_name, apiKey=api_key)
except ClientError as e:
    if e.response["Error"]["Code"] == "ConflictException":
        cred = ctrl.get_api_key_credential_provider(name=provider_name)
    else:
        raise
cred_arn = cred["credentialProviderArn"]
print("[1/2] Stored key in AgentCore Identity:", cred_arn)

# Auto-detect the exact liteLlmModelConfig format accepted by AgentCore + Groq
candidates = [
    {"modelId": "groq/openai/gpt-oss-20b", "apiKeyArn": cred_arn, "maxTokens": 2048, "temperature": 0.1},
    {"modelId": "groq/openai/gpt-oss-20b", "apiKeyArn": cred_arn, "apiBase": "https://api.groq.com/openai/v1", "maxTokens": 2048, "temperature": 0.1},
    {"modelId": "groq/openai/gpt-oss-120b", "apiKeyArn": cred_arn, "maxTokens": 2048, "temperature": 0.1},
]

winner = None
for mcfg in candidates:
    t0 = time.time()
    try:
        resp = rt.invoke_harness(
            harnessArn=cfg["harness_arn"],
            runtimeSessionId=str(uuid.uuid4()).ljust(36, "0"),
            model={"liteLlmModelConfig": mcfg},
            timeoutSeconds=25,
            messages=[{"role": "user", "content": [{"text": "Reply with one word: READY"}]}],
        )
        txt, reason = [], "unknown"
        for e in resp.get("stream", []):
            if "contentBlockDelta" in e and "text" in e["contentBlockDelta"].get("delta", {}):
                txt.append(e["contentBlockDelta"]["delta"]["text"])
            elif "messageStop" in e:
                reason = e["messageStop"].get("stopReason", "unknown")
        out = "".join(txt).strip()
        print(f"      Tried {mcfg['modelId']} (apiBase={'yes' if 'apiBase' in mcfg else 'no'}) -> {time.time()-t0:.1f}s | stop={reason} | reply={out[:80]}")
        if reason == "end_turn" and out:
            winner = mcfg
            break
    except Exception as e:
        print(f"      Tried {mcfg['modelId']} -> ERROR: {str(e)[:180]}")

if not winner:
    raise SystemExit("No Groq LiteLLM config succeeded—paste the error lines above.")

cfg["litellm_model_config"] = winner
with open("config.json", "w") as f:
    json.dump(cfg, f, indent=2)
print(f"\n[2/2] WINNER LOCKED: {winner['modelId']} -> saved to config.json!")
