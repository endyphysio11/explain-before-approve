# Package-management actions

## Supported managers

Apply these rules to npm, pnpm, yarn, pip, pipx, brew, and apt.

## Risk distinctions

- Treat list, show, freeze, outdated, and non-fixing audit operations as LOW.
- Treat an ordinary project install, uninstall, or update as MODERATE.
- Treat global, user-wide, system-wide, or privileged changes as HIGH.
- Treat package scripts as at least MODERATE because lifecycle code can have effects beyond dependency files.

Do not call a package malicious without evidence. Explain location and scope instead.

## Impact and recovery

Mention lockfiles, manifests, installed code, executable commands, and environment changes. Restoring dependency files or uninstalling packages often reverses package state, but lifecycle-script side effects may require separate recovery.

## Safer steps

Recommend pinning an explicit version, checking the package source, reviewing lifecycle scripts, avoiding global installation, and inspecting manifest/lockfile diffs.
