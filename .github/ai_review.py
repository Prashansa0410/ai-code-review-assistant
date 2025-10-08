import os, json, requests

REPO = os.environ.get("GITHUB_REPOSITORY")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

def read_event_payload():
    """Reads GitHub event data (like PR number)."""
    path = os.environ.get("GITHUB_EVENT_PATH")
    with open(path) as f:
        return json.load(f)

def post_comment(pr_number, body):
    """Posts a comment on the PR."""
    url = f"https://api.github.com/repos/{REPO}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }
    requests.post(url, headers=headers, json={"body": body}, timeout=30)

def main():
    ev = read_event_payload()
    pr_number = ev["number"]
    body = "🤖 Hello! The AI review bot pipeline is working. 🚀"
    post_comment(pr_number, body)

if __name__ == "__main__":
    main()
