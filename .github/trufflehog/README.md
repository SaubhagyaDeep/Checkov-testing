# TruffleHog shared workflow

- `.github/actions/trufflehog-scan` — composite action: scan (verified only, image pinned by digest), redact, apply allowlist.
- `.github/workflows/trufflehog.yml` — `workflow_call` wrapper: sticky PR comment, Slack alert on full scans, optional blocking.
- `.github/workflows/trufflehog-scan.yml` — this repo's own caller.

## Using it from another repo
Pin the workflow by commit SHA with the release tag in a trailing comment. Add this to the caller repo so Dependabot opens PRs for new releases:
```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: github-actions
    directory: /
    schedule: { interval: weekly }
```
Releasing: change the action, bump the action SHA pinned inside `trufflehog.yml` by hand (a repo can't usefully auto-bump its own pin), then tag the workflow commit `vX.Y.Z`.

```yaml
name: TruffleHog
on:
  pull_request: { branches: [main] }
  schedule: [{ cron: '0 6 1,15 * *' }]   # full history
  workflow_dispatch:
permissions: { contents: read, pull-requests: write }
jobs:
  trufflehog:
    uses: SaubhagyaDeep/Checkov-testing/.github/workflows/trufflehog.yml@<commit-sha> # v1.0.0
    with:
      scan: ${{ github.event_name == 'pull_request' && 'pr' || 'full' }}
      results: verified,unverified   # per-repo toggle; `verified` for low noise
      mode: report                   # report (never fails) | block (fails on ANY finding)
    secrets: inherit
```
Add `.github/trufflehog/allowlist.yaml` (`allowlist: []`) and a CODEOWNERS entry for it.

## Allowlist
Entries apply in the same PR; suppressed findings are listed in the PR comment. Require code-owner review on the file.
`expires` is a date (max 180 days out) or `never`. `reason` and `approved-by` are always required.
