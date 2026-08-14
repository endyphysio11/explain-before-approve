# Filesystem actions

## Scope controls risk

- Treat ordinary reads such as `ls`, `pwd`, `find`, and non-sensitive `cat` as LOW.
- Treat creation, copying, moving, redirection, and single-file deletion as MODERATE when scope is explicit.
- Treat recursive deletion of an ordinary non-generated directory as HIGH.
- Treat deletion of `.` or all current-directory contents as HIGH and normally `DO_NOT_APPROVE`.
- Treat deletion of `/`, home roots, system roots, or broad user roots as CRITICAL and `DO_NOT_APPROVE`.
- Treat known generated directories such as `node_modules`, build output, and caches as MODERATE when the exact target is clear.

## Overwrite and permissions

Surface uncertainty when a destination may already exist. Treat recursive or root-level `chmod` and `chown` as HIGH; limited explicit changes are normally MODERATE.

## Recovery

Do not promise an undo. Version control may restore tracked files, but untracked work needs backups or filesystem recovery. Forced deletion may bypass easy recovery.

## Safer steps

Recommend listing exact targets, removing recursive/force flags, choosing one explicit disposable path, preserving a backup, or using a dry run where available.
