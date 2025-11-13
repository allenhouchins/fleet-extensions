# Git Workflow Reference

**Fork:** https://github.com/tux234/fleet-extensions
**Upstream:** https://github.com/allenhouchins/fleet-extensions

---

## Current Setup

```bash
# Your remotes are configured:
origin    → git@github.com:tux234/fleet-extensions.git (your fork)
upstream  → git@github.com:allenhouchins/fleet-extensions.git (boss's repo)

# Current branch: tux234-add-ubuntu-pro
# Status: ✅ Pushed to your fork
```

---

## What Just Happened

1. ✅ Updated `origin` remote to point to YOUR fork
2. ✅ Added `upstream` remote to track boss's original repo
3. ✅ Committed ubuntu_pro extension (6 files, 1135 lines)
4. ✅ Pushed to your fork: `origin/tux234-add-ubuntu-pro`

---

## Next Steps: Create Pull Request

### Option 1: Via GitHub Link (Easiest)

GitHub gave you this link:
```
https://github.com/tux234/fleet-extensions/pull/new/tux234-add-ubuntu-pro
```

**Just click that link** and it will open a PR creation page!

### Option 2: Via GitHub UI

1. Go to https://github.com/tux234/fleet-extensions
2. You'll see a banner: "tux234-add-ubuntu-pro had recent pushes"
3. Click **"Compare & pull request"**
4. Fill in PR details:
   - **Title:** "Add Ubuntu Pro extension"
   - **Description:** (see template below)
5. Click **"Create pull request"**

### PR Description Template

```markdown
## Summary

Adds a new `ubuntu_pro` extension that exposes Ubuntu Pro (Ubuntu Advantage) subscription information as a native osquery table.

## What This Extension Does

- Provides `ubuntu_pro_status` table with 20 columns
- Tracks Ubuntu Pro contract expiration dates
- Monitors service states (ESM-Infra, ESM-Apps, Livepatch, FIPS, CIS)
- Supports amd64 and arm64 Ubuntu architectures
- Includes automated Fleet installer script

## Pattern Consistency

This extension follows the exact same patterns as `snap_packages`:
- Same main.go structure with socket path handling
- Same Makefile with architecture-specific builds
- Same installer script pattern (architecture detection, GitHub release download)
- Same directory structure (`/var/fleetd/extensions/`)

## Files Added

- `ubuntu_pro/main.go` - Extension implementation
- `ubuntu_pro/Makefile` - Build system
- `ubuntu_pro/go.mod` - Dependencies
- `ubuntu_pro/README.md` - Documentation
- `ubuntu_pro/install-ubuntu-pro-extension.sh` - Fleet installer
- `ubuntu_pro/INTEGRATION.md` - Integration guide

## Use Cases

- Monitor Ubuntu Pro compliance across Fleet
- Alert on expiring contracts (< 30 days)
- Track ESM/Livepatch enablement for security posture
- FIPS compliance reporting

## Example Query

\`\`\`sql
SELECT
  h.hostname,
  p.attached,
  p.contract_expires,
  p.days_until_expiration,
  p.esm_infra_status
FROM system_info h
JOIN ubuntu_pro_status p;
\`\`\`

## Testing

Tested locally with `make build` - builds successfully for both architectures.

## Next Steps After Merge

1. Create GitHub release with compiled binaries
2. Deploy installer script via Fleet
3. Add to README.md extensions table
```

---

## Common Git Workflows

### Keep Your Fork Updated

```bash
# Fetch latest from upstream (boss's repo)
git fetch upstream

# Update your main branch
git checkout main
git merge upstream/main
git push origin main
```

### Make More Changes to Your PR

```bash
# Make edits to files
vim ubuntu_pro/main.go

# Commit and push (automatically updates PR)
git add ubuntu_pro/
git commit -m "Fix: Handle missing ubuntu-advantage-tools package"
git push origin tux234-add-ubuntu-pro
```

### Create a New Feature Branch

```bash
# Always branch from latest main
git checkout main
git pull upstream main

# Create new branch
git checkout -b tux234-add-windows-defender
# ... make changes ...
git push -u origin tux234-add-windows-defender
```

### If Boss Requests Changes

```bash
# Make the requested changes
vim ubuntu_pro/README.md

# Commit with descriptive message
git add ubuntu_pro/README.md
git commit -m "docs: Add example for FIPS compliance query"

# Push (updates the PR automatically)
git push origin tux234-add-ubuntu-pro
```

---

## Useful Git Commands

```bash
# See what remote you're tracking
git remote -v

# See local and remote branches
git branch -vv

# See commit history
git log --oneline -10

# See what's changed
git status

# See diff of your changes
git diff

# Undo last commit (keeps changes)
git reset --soft HEAD~1

# See who changed what in a file
git blame ubuntu_pro/main.go
```

---

## Keeping Your Work Safe

### Your work is now in 3 places:

1. **Local:** `/Users/mitch/code/clone/fleet-extensions/`
2. **Your Fork (GitHub):** https://github.com/tux234/fleet-extensions
3. **Branch:** `tux234-add-ubuntu-pro`

Even if you mess up locally, your work is safe on GitHub!

### To recover if you mess up locally:

```bash
# Throw away all local changes and reset to what's on GitHub
git fetch origin
git reset --hard origin/tux234-add-ubuntu-pro
```

---

## Quick Reference

| Command | What It Does |
|---------|--------------|
| `git fetch upstream` | Get latest from boss's repo |
| `git pull origin tux234-add-ubuntu-pro` | Get latest from your fork |
| `git push origin tux234-add-ubuntu-pro` | Push changes to your fork |
| `git status` | See what's changed |
| `git log --oneline -5` | See recent commits |
| `git remote -v` | See configured remotes |

---

**Your branch is pushed and ready for a PR!** 🎉

Just click: https://github.com/tux234/fleet-extensions/pull/new/tux234-add-ubuntu-pro
