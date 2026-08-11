---
name: github-integration
description: Use when interacting with GitHub for code review, issues, PRs, CI checks, or API operations. Trigger on mentions of PR, issue, CI, code review, merge, branch, release, or when checking build status. Requires `gh` CLI installed and authenticated.
---

# GitHub Integration

## Prerequisites

- `gh` CLI installed (`winget install GitHub.cli` or `choco install gh`)
- Authenticated: `gh auth status` should show logged in
- Run `gh auth login` if not authenticated

## Common Operations

### Pull Requests

```bash
# List open PRs
gh pr list

# View PR details
gh pr view <number>

# View PR diff
gh pr diff <number>

# Create PR
gh pr create --title "feat: ..." --body "..."

# Merge PR
gh pr merge <number> --squash --delete-branch

# Request changes / approve
gh pr review <number> --approve
gh pr review <number> --request-changes --body "..."
```

### Code Review

```bash
# List files in PR
gh pr diff <number> --name-only

# View specific file diff
gh pr diff <number> -- path/to/file.rs

# Add review comment on specific line
gh api repos/{owner}/{repo}/pulls/<number>/comments \
  -f body="Suggestion" \
  -f commit_id="<sha>" \
  -f path="file.rs" \
  -f line=<line_number>
```

### Issues

```bash
# List issues
gh issue list --state open

# Create issue
gh issue create --title "..." --label "bug" --assignee "@me"

# Close issue
gh issue close <number>
```

### CI / Checks

```bash
# View workflow runs
gh run list --limit 10

# View specific run
gh run view <run_id>

# View failed job logs
gh run view <run_id> --log-failed

# Re-run failed jobs
gh run rerun <run_id> --failed

# Watch run in real-time
gh run watch <run_id>
```

### Repository Info

```bash
# View repo details
gh repo view

# List branches
gh api repos/{owner}/{repo}/branches --jq '.[].name'

# Create release
gh release create v1.0.0 --notes "Release notes"

# View latest release
gh release view
```

## API Queries

```bash
# Search repos
gh search repos "query" --limit 5

# Search code
gh search code "function_name" --repo owner/repo

# Get rate limit
gh api rate_limit --jq '.rate'
```

## Workflow for Code Review

1. `gh pr list` — find open PRs
2. `gh pr view <n>` — read description and context
3. `gh pr diff <n>` — analyze changes
4. `gh api .../pulls/<n>/comments` — post line-specific feedback
5. `gh pr review <n> --approve` or `--request-changes`

## Workflow for CI Debug

1. `gh run list --limit 5` — find recent failures
2. `gh run view <id> --log-failed` — read error output
3. Cross-reference with source code
4. Fix and push

## Tips

- Always check `gh auth status` before assuming access
- Use `--jq` to filter JSON output from `gh api`
- For repos not in current directory, use `--repo owner/repo` flag
- Rate limit: 5000 requests/hour for authenticated users
