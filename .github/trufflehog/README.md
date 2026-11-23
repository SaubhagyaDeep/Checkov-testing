# TruffleHog secret scanning

- `../workflows/trufflehog-pr.yml` — every PR to `main`; scans only the PR's commits, verified secrets only.
  Posts one sticky, redacted comment (no secret values).
- `../workflows/trufflehog-full-scan.yml` — 1st/15th of each month + manual; full history. Verified findings
  go to the SecOps Slack channel (secret `SECOPS_SLACK_WEBHOOK_URL`).
- `allowlist.yaml` — reviewable exceptions. Each entry needs `reason`, `expires` (≤180 days), `approved-by`.
  Expired entries stop applying automatically.
- `process_findings.py` — strips raw secret material, applies the allowlist, builds the comment.

## Monitoring → blocking
The PR check never fails on findings until the repo/org variable `TRUFFLEHOG_ENFORCE` is set to `true`.
Flip it once the full-history scan is clean (or every remaining finding is rotated or allowlisted).
Then add the `TruffleHog verified-secret scan` job as a required status check on `main`.

## Upgrading TruffleHog
Bump the image digest in both workflows together. Get it with:
`gh api repos/trufflesecurity/trufflehog/releases/latest --jq .tag_name`, then read the
`docker-content-digest` header for `ghcr.io/trufflesecurity/trufflehog:<version without v>`.
Action commit for v3.100.0 (if you prefer the action): `d232362a64a09a9e7d58267b8f5acef00ae90e23`.
