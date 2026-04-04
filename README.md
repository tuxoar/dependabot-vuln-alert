# dependabot-vuln-alert

Pulls all open Dependabot alerts for a GitHub org, personal account, or specific repos — summarizes by repo and posts a report to Slack.

Supports **PAT/fine-grained token** or **GitHub App** authentication, and works with GitHub.com and GitHub Enterprise Server.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GITHUB_ORG` | one of org/user | GitHub organization to scan |
| `GITHUB_USER` | one of org/user | Personal GitHub username to scan |
| `SLACK_WEBHOOK_URL` | yes | Slack incoming webhook URL |
| **Token auth** | | |
| `GITHUB_TOKEN` | one of token/app | PAT or fine-grained token with `security_events` scope |
| **GitHub App auth** | | |
| `GITHUB_APP_ID` | one of token/app | App ID |
| `GITHUB_APP_KEY` | one of key/path | PEM private key contents (for CI/CD) |
| `GITHUB_APP_KEY_PATH` | one of key/path | Path to `.pem` private key file (for local/Docker) |
| `GITHUB_INSTALL_ID` | optional | Installation ID (auto-detected from org/user if omitted) |
| **Optional** | | |
| `GITHUB_BASE_URL` | no | API base URL (default `https://api.github.com`). Set for GHE. |
| `GITHUB_REPOS` | no | Comma-separated list of repos (e.g. `repo1,repo2` or `owner/repo1,owner/repo2`) |
| `ALERT_STATE` | no | Alert state filter (default `open`) |
| `ALERT_SEVERITY` | no | Comma-separated severity filter (default `critical,high,medium`) |

> `GITHUB_APP_KEY` (raw PEM) takes precedence over `GITHUB_APP_KEY_PATH` (file path) when both are set.

## Quick Start

### Option 1: Personal Access Token

```bash
export GITHUB_TOKEN=ghp_...
export GITHUB_USER=my-username
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
go run .
```

### Option 2: GitHub App (recommended)

#### Create the app with `gh` CLI

```bash
gh api orgs/{ORG}/apps \
  --method POST \
  -f name="Dependabot Alert Reader" \
  -f url="https://github.com/{ORG}" \
  -f default_permissions='{"vulnerability_alerts":"read","metadata":"read"}' \
  -f default_events='[]' \
  --jq '.id, .pem, .client_id'
```

For a personal account, use the user endpoint instead:

```bash
gh api user/apps \
  --method POST \
  -f name="Dependabot Alert Reader" \
  -f url="https://github.com/{USER}" \
  -f default_permissions='{"vulnerability_alerts":"read","metadata":"read"}' \
  -f default_events='[]' \
  --jq '.id, .pem, .client_id'
```

> **Note:** The response includes the app ID and private key. Save the PEM output immediately — it is only shown once.

```bash
# Save the private key securely
mkdir -p ~/.github-apps && chmod 700 ~/.github-apps
# Paste the PEM output into this file
vim ~/.github-apps/dependabot-reader.pem
chmod 600 ~/.github-apps/dependabot-reader.pem
```

Then install the app on your account/org via **Settings → GitHub Apps → Install**, and run:

```bash
export GITHUB_APP_ID=12345
export GITHUB_APP_KEY_PATH=~/.github-apps/dependabot-reader.pem
export GITHUB_ORG=my-org   # or GITHUB_USER=my-username
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
go run .
```

### Scan specific repos only

```bash
export GITHUB_REPOS=vuln-report,OSWE,other-repo
# or with full owner/repo paths:
export GITHUB_REPOS=my-org/repo1,other-org/repo2
go run .
```

### Filter by severity

```bash
# Only critical and high (default includes medium)
export ALERT_SEVERITY=critical,high
go run .

# Include everything
export ALERT_SEVERITY=critical,high,medium,low
go run .
```

## Docker

```bash
docker build -t dependabot-vuln-alert .

# With PAT
docker run --rm \
  -e GITHUB_TOKEN -e GITHUB_ORG -e SLACK_WEBHOOK_URL \
  dependabot-vuln-alert

# With GitHub App — mount key file
docker run --rm \
  -e GITHUB_APP_ID -e GITHUB_APP_KEY_PATH=/secrets/app.pem \
  -e GITHUB_ORG -e SLACK_WEBHOOK_URL \
  -v ~/.github-apps/dependabot-reader.pem:/secrets/app.pem:ro \
  dependabot-vuln-alert

# With GitHub App — pass key as env var (CI/CD)
docker run --rm \
  -e GITHUB_APP_ID \
  -e GITHUB_APP_KEY="${APP_PRIVATE_KEY}" \
  -e GITHUB_ORG -e SLACK_WEBHOOK_URL \
  dependabot-vuln-alert
```

> The distroless image runs as non-root (UID 65534) with no shell.

## How it works

1. Authenticates via PAT or GitHub App (generates JWT → exchanges for short-lived installation token)
2. If `GITHUB_REPOS` is set, fetches alerts for those repos only
3. For orgs, tries the bulk `/orgs/{org}/dependabot/alerts` endpoint first (single API call)
4. For personal accounts or as fallback, lists repos then checks each for alerts
5. Filters by severity (default: critical, high, medium), sorts by criticality
6. Posts a Slack Block Kit message with per-repo sections, capped at 50 alerts per repo

## GitHub App Permissions

The app only needs:
- **Repository permissions**: Dependabot alerts (read), Metadata (read)
- **No webhook** required
- **No write access** needed
