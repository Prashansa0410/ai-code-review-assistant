import os, json, subprocess, re, time, requests, sys
from typing import List, Dict, Any, Tuple

REPO = os.environ.get("GITHUB_REPOSITORY")
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
LLM_API_KEY = os.environ.get("LLM_API_KEY", "")
MODEL_NAME = os.environ.get("MODEL_NAME", "gpt-4o-mini")
CONFIDENCE_MIN = float(os.environ.get("CONFIDENCE_MIN", "0.4"))
DRY_RUN = bool(os.environ.get("DRY_RUN", ""))

def run(cmd: str) -> str:
    return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.STDOUT).strip()

def read_event_payload() -> dict:
    with open(os.environ["GITHUB_EVENT_PATH"]) as f:
        return json.load(f)

def get_pr_number(ev: dict) -> int:
    if "number" in ev: return int(ev["number"])
    return int((ev.get("pull_request") or {}).get("number", 0))

def get_base_head_shas(ev: dict) -> Tuple[str, str]:
    pr = ev.get("pull_request") or {}
    base = (pr.get("base") or {}).get("sha")
    head = (pr.get("head") or {}).get("sha")
    if base and head: return base, head
    # local fallback
    base = run("git merge-base origin/HEAD HEAD")
    head = run("git rev-parse HEAD")
    return base, head

def get_diff(base: str, head: str) -> str:
    # unified=3 keeps context tight; safe truncation below
    return run(f"git diff --unified=3 {base}...{head}")

def parse_changed_files(diff: str) -> List[str]:
    files = re.findall(r'^\+\+\+ b/(.+)$', diff, flags=re.M)
    return sorted(set(f for f in files if f and f != "/dev/null"))

def expand_context(files: List[str], cap_bytes=200_000) -> str:
    """Grab small slices of touched files to give the model surrounding code."""
    out = []
    for f in files[:60]:
        try:
            if os.path.exists(f) and os.path.getsize(f) <= cap_bytes:
                with open(f, "r", errors="ignore") as fh:
                    content = fh.read()
                out.append(f"\n# FILE: {f}\n{content[:12000]}")
        except Exception:
            continue
    return "\n".join(out)

def preflight_secret_scan(diff: str) -> List[Dict[str, Any]]:
    rules = [
        (r'AKIA[0-9A-Z]{16}', "Possible AWS Access Key ID"),
        (r'-----BEGIN (?:RSA|EC|PGP) PRIVATE KEY-----', "Private key material"),
        (r'AIza[0-9A-Za-z\-_]{35}', "Possible Google API key"),
        (r'(?i)api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9-_]{16,}["\']', "Generic API key"),
        (r'(?i)secret\s*[:=]\s*["\'][A-Za-z0-9/+=]{16,}["\']', "Generic secret"),
    ]
    findings = []
    for pat, label in rules:
        if re.search(pat, diff):
            findings.append({
                "file": "(diff)",
                "line_range": [0,0],
                "severity": "blocker",
                "confidence": 0.95,
                "rationale": f"{label} detected in diff. Remove and rotate immediately.",
                "patch": None
            })
    return findings

def load_policy_snippets() -> str:
    try:
        with open(".aicodepolicy.md", "r") as f:
            return f.read()[:4000]
    except Exception:
        return ""

def build_prompt(diff: str, ctx: str) -> str:
    policies = load_policy_snippets()
    return f"""
You are a staff-level engineer performing a focused code review.
Be precise and terse. Prefer minimal changes. Never invent APIs. If uncertain, say so.
Return ONLY a JSON array (no extra text).

# PULL REQUEST DIFF (unified)
{diff[:120000]}

# SURROUNDING CONTEXT (read-only)
{ctx[:120000]}

# PROJECT POLICIES (snippets)
{policies}

# OUTPUT JSON SCHEMA
[{{
 "file": "path/to/file",
 "line_range": [start, end],
 "severity": "blocker|major|nit",
 "confidence": 0.0,
 "rationale": "1-3 sentences",
 "patch": "unified diff applying a minimal fix (optional)"
}}]

Rules:
- Cite exact file/line ranges from the provided code only.
- If uncertain, set confidence <= 0.4 and omit patch; propose a clarifying question.
- Prefer minimal, safe fixes. Avoid large refactors.
"""

def call_llm(prompt: str) -> str:
    if not LLM_API_KEY:
        return '[]'  # graceful if key missing
    url = "https://api.openai.com/v1/chat/completions"
    headers = {"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"}
    body = {
        "model": MODEL_NAME,
        "messages": [
            {"role": "system", "content": "You are a precise code reviewer."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.1
    }
    r = requests.post(url, headers=headers, json=body, timeout=120)
    r.raise_for_status()
    return r.json()["choices"][0]["message"]["content"].strip()

def strip_fences(s: str) -> str:
    s = s.strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z0-9]*\n", "", s)
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()

def format_md(findings: List[Dict[str, Any]]) -> str:
    if not findings:
        return "### 🤖 AI Review: LGTM\nNo issues detected; consider adding/expanding tests if logic changed."
    lines = []
    for f in findings:
        patch_block = f"```diff\n{f['patch']}\n```" if f.get("patch") else ""
        lines.append(
            f"**{f['severity'].upper()}** (conf {float(f.get('confidence',0)):.2f}) — `{f.get('file','?')}` lines {f.get('line_range',[0,0])[0]}–{f.get('line_range',[0,0])[1]}\n"
            f"> {f.get('rationale','')}\n{patch_block}"
        )
    return "### 🤖 AI Review Findings\n" + "\n\n".join(lines)

def post_comment(pr_number: int, body: str):
    if DRY_RUN or not GITHUB_TOKEN or not REPO:
        with open("ai_review_output.md","w") as f: f.write(body)
        print("DRY_RUN or missing GitHub context. Wrote ai_review_output.md")
        return
    url = f"https://api.github.com/repos/{REPO}/issues/{pr_number}/comments"
    headers = {"Authorization": f"Bearer {GITHUB_TOKEN}", "Accept": "application/vnd.github+json"}
    requests.post(url, headers=headers, json={"body": body}, timeout=30)

def main():
    start = time.time()
    ev = read_event_payload()
    pr = get_pr_number(ev)
    base, head = get_base_head_shas(ev)
    diff = get_diff(base, head)
    files = parse_changed_files(diff)
    ctx = expand_context(files)

    # Safety: secret scan first
    pre = preflight_secret_scan(diff)

    prompt = build_prompt(diff, ctx)
    try:
        raw = call_llm(prompt)
        raw = strip_fences(raw)
        model_findings = json.loads(raw) if raw else []
        if isinstance(model_findings, dict) and "findings" in model_findings:
            model_findings = model_findings["findings"]
    except Exception as e:
        model_findings = [{
            "file": "(assistant)",
            "line_range": [0,0],
            "severity": "nit",
            "confidence": 0.5,
            "rationale": f"Model call or parsing failed: {e}",
            "patch": None
        }]

    # Merge + filter
    findings = pre + (model_findings if isinstance(model_findings, list) else [])
    filtered = []
    for f in findings:
        sev = (f.get("severity","") or "").lower()
        try:
            conf = float(f.get("confidence", 0))
        except Exception:
            conf = 0.0
        if sev == "blocker" or conf >= CONFIDENCE_MIN:
            filtered.append(f)
    findings = filtered[:30]  # cap noise

    # Metrics (simple JSONL)
    metrics = {
        "ts": int(time.time()),
        "pr": pr,
        "model": MODEL_NAME,
        "runtime_s": round(time.time()-start, 3),
        "findings_total": len(findings),
        "blockers": sum(1 for x in findings if (x.get("severity","").lower() == "blocker"))
    }
    try:
        with open("ai_review_metrics.jsonl","a") as m:
            m.write(json.dumps(metrics)+"\n")
    except Exception:
        pass

    body = format_md(findings)
    post_comment(pr, body)

if __name__ == "__main__":
    main()
