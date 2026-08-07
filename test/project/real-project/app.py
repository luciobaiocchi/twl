import json
import os
import urllib.request


key = os.environ["GEMINI_API_KEY"]
base_url = os.environ["GEMINI_BASE_URL"].rstrip("/")
model = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")

if not key.startswith("twl-app-"):
    raise SystemExit("GEMINI_API_KEY is not a synthetic Towel key")

print(f"GEMINI_API_KEY={key}")
print(f"GEMINI_BASE_URL={base_url}")

payload = {
    "model": model,
    "messages": [{"role": "user", "content": "Describe this test environment."}],
    "max_tokens": 128,
}
if model == "gemini-2.5-flash":
    payload["reasoning_effort"] = "none"

request = urllib.request.Request(
    f"{base_url}/chat/completions",
    data=json.dumps(payload).encode(),
    headers={
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
    },
    method="POST",
)

with urllib.request.urlopen(request, timeout=30) as response:
    print(json.dumps(json.load(response), indent=2))
