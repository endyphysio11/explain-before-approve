# Git actions

## Read-only and remote reads

- Treat `status`, `diff`, `log`, and `show` as LOW when no write action is chained.
- Treat `fetch` as LOW: it updates remote-tracking metadata but does not merge working files.
- Treat `pull` as MODERATE because it integrates remote changes into local history and files.

## Publishing and shared state

- Treat an ordinary `push` as HIGH because it changes shared remote state.
- Treat force push and `--force-with-lease` as HIGH. The lease reduces race risk but still rewrites visible remote history.
- Raise concern for `main`, `master`, protected branches, branch deletion, and tag deletion.
- Explain that published changes may affect collaborators and automation.

## Destructive local operations

- Treat `reset --hard` and non-preview `clean` as HIGH.
- Explain that the reflog may recover committed objects but not necessarily uncommitted or untracked files.
- Treat `git clean --dry-run` as LOW and recommend it before actual cleanup.
- Treat local rebase, checkout, restore, branch deletion, and tag deletion as MODERATE unless the visible scope discards broad working state.

## Safer steps

Recommend `git status`, a saved diff, a temporary branch, `git fetch`, comparison of outgoing/incoming commits, or dry-run cleanup as appropriate.
