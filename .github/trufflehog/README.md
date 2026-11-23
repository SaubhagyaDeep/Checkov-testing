# TruffleHog shared workflow

- `.github/actions/trufflehog-scan` — composite action: scan (verified only, image pinned by digest), redact, apply allowlist.
- `.github/workflows/trufflehog.yml` — `workflow_call` wrapper: sticky PR comment, Slack alert on full scans, optional blocking.
- `.github/workflows/trufflehog-scan.yml` — this repo's own caller.

## Using it from another repo
Pin the workflow by commit SHA (tell the caller to bump it after each release: change the action, then bump the SHA in `trufflehog.yml`).

```yaml
name: TruffleHog
on:
  pull_request: { branches: [main] }
  schedule: [{ cron: '0 6 1,15 * *' }]   # full history
  workflow_dispatch:
permissions: { contents: read, pull-requests: write }
jobs:
  trufflehog:
    uses: SaubhagyaDeep/Checkov-testing/.github/workflows/trufflehog.yml@<commit-sha>
    with:
      scan: ${{ github.event_name == 'pull_request' && 'pr' || 'full' }}
      mode: report        # report | block
    secrets: inherit
```
Add `.github/trufflehog/allowlist.yaml` (`allowlist: []`) and a CODEOWNERS entry for it.

## Allowlist
Entries apply in the same PR; suppressed findings are listed in the PR comment. Require code-owner review on the file.
caller test
