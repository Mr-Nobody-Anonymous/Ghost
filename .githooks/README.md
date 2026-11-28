# Git hooks

Install once per clone:

```bash
git config core.hooksPath .githooks
```

| Hook | Runs | Why |
|---|---|---|
| `pre-commit` | ruff, the test suite, fixture freshness | The full gate takes ~9 s and needs the network; the fast subset catches the mistakes that actually reach commits |
| `commit-msg` | subject-length and placeholder-subject check | This repository's early history is a run of "fix" and "update" entries that explain nothing |

Bypass either with `git commit --no-verify`. CI runs `ci/gate.sh` in full, so a
bypassed commit cannot be merged without passing everything anyway.

Nothing here is installed automatically: `git config` is a local setting and a
hook that installs itself is a hook nobody trusts.
