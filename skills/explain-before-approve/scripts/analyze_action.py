#!/usr/bin/env python3
"""Deterministically explain candidate actions without ever executing them.

Candidate text is untrusted data. This module only compares, tokenizes, and
classifies strings with Python's standard library.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
from typing import Any


RISK_ORDER = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "CRITICAL": 3}
RECOMMENDATION_ORDER = {
    "SAFE_TO_APPROVE": 0,
    "REVIEW_FIRST": 1,
    "DO_NOT_APPROVE": 2,
}
RISK_LABELS = {
    "LOW": "🟢 LOW",
    "MODERATE": "🟡 MODERATE",
    "HIGH": "🟠 HIGH",
    "CRITICAL": "🔴 CRITICAL",
}

REQUIRED_FIELDS = (
    "domain",
    "risk",
    "recommendation",
    "action_summary",
    "impact",
    "reversibility",
    "safer_alternatives",
    "uncertainties",
    "signals",
)

SECRET_FILE_RE = re.compile(
    r"(?:^|[\s/\\'\"])(?:\.env(?:\.[\w.-]+)?|id_(?:rsa|ed25519|ecdsa|dsa|sk)|"
    r"(?:credentials|secrets)(?:\.(?:json|ya?ml|toml|ini))?|service[-_]?account(?:\.json)?|\.aws/credentials|"
    r"\.ssh/(?:config|authorized_keys)|\.npmrc|\.pypirc|\.netrc|"
    r"\.docker/config\.json|\.kube/config|application_default_credentials\.json|"
    r"\.git-credentials|\.pgpass|\.mylogin\.cnf|\.vault-token|\.htpasswd|"
    r"(?:private|client|server)[-_]?[\w.-]*\.(?:pem|key))"
    r"(?:$|[\s'\"])",
    re.IGNORECASE,
)
SECRET_NAME_PATTERN = (
    r"(?:[A-Z][A-Z0-9]*[_-])*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|AUTH[_-]?TOKEN|TOKEN|"
    r"DATABASE[_-]?(?:URL|PASSWORD)|DB[_-]?(?:PASSWORD|PASS)|SECRET(?:[_-]?KEY)?|"
    r"PRIVATE[_-]?KEY|PASSWORD|PASS|ACCESS[_-]?KEY(?:[_-]?ID)?|SESSION[_-]?TOKEN)"
)
SECRET_FIELD_PATTERN = (
    r"(?:" + SECRET_NAME_PATTERN + r"|CREDENTIALS?|PASSWD)"
    r"(?:[_-](?:HASH|DIGEST|VERIFIER|VALUE|SALT))?"
)
SECRET_VAR_RE = re.compile(
    r"(?:\$(?:\{!?|!)?" + SECRET_NAME_PATTERN + r"(?![A-Z0-9_-])(?:\})?"
    r"|\$env:" + SECRET_NAME_PATTERN + r"(?![A-Z0-9_-])"
    r"|\$\{env:" + SECRET_NAME_PATTERN + r"\}"
    r"|%" + SECRET_NAME_PATTERN + r"(?:[:][^%]*)?%"
    r"|!" + SECRET_NAME_PATTERN + r"!)",
    re.IGNORECASE,
)
SECRET_NAME_RE = re.compile(r"^" + SECRET_NAME_PATTERN + r"$", re.IGNORECASE)
SECRET_ENVIRONMENT_GETTER_RE = re.compile(
    r"\[\s*(?:System\.)?Environment\s*\]\s*::\s*GetEnvironmentVariable\s*\(\s*"
    r"['\"]\s*" + SECRET_NAME_PATTERN + r"\s*['\"]\s*\)",
    re.IGNORECASE,
)
SECRET_MOUNT_RE = re.compile(
    r"(?:^|/)(?:run|var/run)/(?:secrets?|credentials?)(?:/|$)|"
    r"(?:^|/)(?:secrets?|credentials?)/(?:[^/]+/)*" + SECRET_NAME_PATTERN + r"(?:$|[./])",
    re.IGNORECASE,
)
PRODUCTION_RE = re.compile(
    r"(?:--(?:env(?:ironment)?[=\s]+)?prod(?:uction)?\b|\bproduction\b|"
    r"\bprod[-_.](?:db|database|cluster|server)\b|\bDATABASE_URL=[^\s]*(?:prod|production))",
    re.IGNORECASE,
)
NETWORK_TRANSFER_COMMANDS = {
    "curl", "wget", "scp", "sftp", "ssh", "ftp", "nc", "netcat", "rsync", "socat"
}
GIT_RECOGNIZED_OPERATIONS = {
    "status", "diff", "log", "show", "fetch", "pull", "push", "reset", "clean",
    "rebase", "checkout", "restore", "branch", "tag", "add", "commit", "clone",
}
GIT_BUILTIN_COMMANDS = GIT_RECOGNIZED_OPERATIONS | {
    "apply", "archive", "bisect", "blame", "bundle", "cherry-pick", "config", "describe",
    "format-patch", "gc", "grep", "init", "merge", "mv", "notes", "reflog", "remote",
    "revert", "rm", "shortlog", "stash", "submodule", "switch", "worktree",
}
SQL_MUTATING_SELECT_FUNCTIONS = {
    "nextval", "setval", "pg_advisory_lock", "pg_advisory_xact_lock", "pg_notify",
    "set_config", "pg_reload_conf",
}
SQL_DESTRUCTIVE_SELECT_FUNCTIONS = {
    "lo_unlink", "pg_terminate_backend", "pg_cancel_backend", "dblink_exec",
}
SQL_READ_ONLY_FUNCTIONS = {
    "abs", "array_agg", "avg", "ceil", "char_length", "coalesce", "concat", "count",
    "floor", "json_agg", "jsonb_agg", "length", "lower", "max", "md5", "min", "nullif",
    "now", "round", "substr", "substring", "sum", "upper",
}


def _unique(items: list[str]) -> list[str]:
    """Return non-empty strings in first-seen order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _result(
    domain: str,
    risk: str,
    recommendation: str,
    summary: str,
    impact: list[str],
    reversibility: str,
    safer: list[str],
    uncertainties: list[str] | None = None,
    signals: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "domain": domain,
        "risk": risk,
        "recommendation": recommendation,
        "action_summary": summary,
        "impact": _unique(impact),
        "reversibility": reversibility,
        "safer_alternatives": _unique(safer),
        "uncertainties": _unique(uncertainties or []),
        "signals": _unique(signals or []),
    }


def _combine_analyses(
    analyses: list[dict[str, Any]],
    sub_actions: list[str],
    summary_prefix: str = "This compound action",
) -> dict[str, Any]:
    """Combine inert sub-action results using highest-risk, execution-order precedence."""
    highest_index = max(range(len(analyses)), key=lambda i: RISK_ORDER[analyses[i]["risk"]])
    highest = analyses[highest_index]
    domains = _unique([analysis["domain"] for analysis in analyses])
    recommendation = max(
        (analysis["recommendation"] for analysis in analyses),
        key=lambda item: RECOMMENDATION_ORDER[item],
    )
    material = [
        analysis for analysis in analyses if RISK_ORDER[analysis["risk"]] >= RISK_ORDER["MODERATE"]
    ] or analyses
    result = _result(
        highest["domain"],
        highest["risk"],
        recommendation,
        f"{summary_prefix} has {len(analyses)} identifiable parts. Its highest-risk part: {highest['action_summary']}",
        [impact for analysis in material for impact in analysis["impact"]],
        highest["reversibility"],
        [alternative for analysis in material for alternative in analysis["safer_alternatives"]],
        [uncertainty for analysis in material for uncertainty in analysis["uncertainties"]],
        ["compound_action"] + [signal for analysis in analyses for signal in analysis["signals"]],
    )
    result["domains_detected"] = domains
    result["sub_actions"] = sub_actions
    return result


def _tokens(action: str) -> list[str]:
    try:
        return shlex.split(action, posix=True)
    except ValueError:
        return re.findall(r"[^\s]+", action)


def _possible_expanded_tokens(token: str) -> list[str]:
    """Return inert lexical variants where an environment expansion may be empty."""
    collapsed = re.sub(
        r"\$\{[A-Za-z_][A-Za-z0-9_]*(?:(?::[-+?=])[^}]*)?\}",
        "",
        token,
    )
    return _unique([token, collapsed])


def _command_name(tokens: list[str]) -> str:
    """Return the command word after inert assignments and execution wrappers."""
    def basename(token: str) -> str:
        return token.replace("\\", "/").rsplit("/", 1)[-1].lower()

    index = 0
    while index < len(tokens):
        while index < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[index]):
            index += 1
        if index >= len(tokens):
            return ""
        command = basename(tokens[index])
        if command == "env":
            index += 1
            value_options = {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}
            while index < len(tokens):
                token = tokens[index]
                if token in value_options:
                    index += 2
                elif token.startswith(("--unset=", "--chdir=", "--split-string=")):
                    index += 1
                elif token.startswith("-"):
                    index += 1
                elif re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
                    index += 1
                else:
                    break
            continue
        if command == "sudo":
            index += 1
            value_options = {
                "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
                "-C", "--close-from", "-r", "--role", "-t", "--type", "-D", "--chdir",
            }
            while index < len(tokens) and tokens[index].startswith("-"):
                token = tokens[index]
                if token in value_options:
                    index += 2
                else:
                    index += 1
            continue
        if command in {"nohup", "exec"}:
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            continue
        if command == "command":
            if index + 1 < len(tokens) and tokens[index + 1] in {"-v", "-V"}:
                return "command"
            index += 1
            if index < len(tokens) and tokens[index] == "--":
                index += 1
            continue
        if command == "time":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                token = tokens[index]
                index += 2 if token in {"-f", "--format", "-o", "--output"} else 1
            continue
        if command == "nice":
            index += 1
            if index < len(tokens) and tokens[index] in {"-n", "--adjustment"}:
                index += 2
            while index < len(tokens) and tokens[index].startswith("-"):
                index += 1
            continue
        if command == "timeout":
            index += 1
            while index < len(tokens) and tokens[index].startswith("-"):
                token = tokens[index]
                index += 2 if token in {"-s", "--signal", "-k", "--kill-after"} else 1
            if index < len(tokens):
                index += 1
            continue
        break
    if index >= len(tokens):
        return ""
    return basename(tokens[index])


def _sql_target(action: str, operation: str) -> str:
    patterns = {
        "select": r"\bfrom\s+([\w.`\"\[\]-]+)",
        "insert": r"\binto\s+([\w.`\"\[\]-]+)",
        "update": r"\bupdate\s+([\w.`\"\[\]-]+)",
        "delete": r"\bfrom\s+([\w.`\"\[\]-]+)",
        "drop": r"\bdrop\s+(?:table|database|schema)\s+(?:if\s+exists\s+)?([\w.`\"\[\]-]+)",
        "truncate": r"\btruncate\s+(?:table\s+)?([\w.`\"\[\]-]+)",
        "alter": r"\balter\s+table\s+([\w.`\"\[\]-]+)",
        "create": r"\bcreate\s+(?:table|database|schema)\s+(?:if\s+not\s+exists\s+)?([\w.`\"\[\]-]+)",
    }
    match = re.search(patterns.get(operation, r"$^"), action, re.IGNORECASE)
    return match.group(1).strip("`\"[]") if match else "the specified target"


def _sql_clause(action: str, keyword: str) -> str:
    masked = _mask_sql_literals(action)
    start_match = re.search(rf"\b{keyword}\b", masked, re.IGNORECASE)
    if not start_match:
        return ""
    start = start_match.end()
    tail = masked[start:]
    end_match = re.search(r"\bwhere\b|;|--|$", tail, re.IGNORECASE) if keyword == "set" else re.search(r";|--|$", tail)
    end = start + (end_match.start() if end_match else len(tail))
    return re.sub(r"\s+", " ", action[start:end]).strip()


def _mask_sql_literals(sql: str) -> str:
    """Mask quoted SQL values/comments while preserving keyword positions."""
    output = list(sql)
    quote: str | None = None
    index = 0
    while index < len(sql):
        char = sql[index]
        following = sql[index + 1] if index + 1 < len(sql) else ""
        if quote:
            output[index] = " "
            if char == "\\" and following:
                output[index + 1] = " "
                index += 2
                continue
            if char == quote:
                if following == quote:
                    output[index + 1] = " "
                    index += 2
                    continue
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            output[index] = " "
            index += 1
            continue
        if char == "$":
            delimiter_match = re.match(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$", sql[index:])
            if delimiter_match:
                delimiter = delimiter_match.group(0)
                end = sql.find(delimiter, index + len(delimiter))
                end = len(sql) if end == -1 else end + len(delimiter)
                output[index:end] = [" "] * (end - index)
                index = end
                continue
        if char == "[":
            end = sql.find("]", index + 1)
            end = len(sql) if end == -1 else end + 1
            output[index:end] = [" "] * (end - index)
            index = end
            continue
        if char == "-" and following == "-":
            end = sql.find("\n", index)
            end = len(sql) if end == -1 else end
            output[index:end] = [" "] * (end - index)
            index = end
            continue
        if char == "/" and following == "*":
            end = sql.find("*/", index + 2)
            end = len(sql) if end == -1 else end + 2
            output[index:end] = [" "] * (end - index)
            index = end
            continue
        index += 1
    return "".join(output)


def _expand_mysql_executable_comments(sql: str) -> str:
    """Expose code inside MySQL /*! ... */ comments for conservative analysis."""
    return re.sub(
        r"/\*!\s*\d*\s*(.*?)\*/",
        lambda match: " " + match.group(1) + " ",
        sql,
        flags=re.DOTALL,
    )


def _split_sql_statements(sql: str) -> list[str]:
    sql = _expand_mysql_executable_comments(sql)
    masked = _mask_sql_literals(sql)
    parts: list[str] = []
    start = 0
    for index, char in enumerate(masked):
        if char == ";":
            statement = sql[start:index].strip()
            if statement:
                parts.append(statement)
            start = index + 1
    tail = sql[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _database_client_statements(action: str) -> list[str]:
    tokens = _tokens(action)
    client = _command_name(tokens)
    if client not in {"psql", "mysql", "sqlite3", "sqlcmd"}:
        return []
    statements: list[str] = []
    options = {
        "-c", "--command", "-e", "--execute", "-q", "--init-command", "--init-command-add"
    }
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lowered = token.lower()
        if lowered in options and index + 1 < len(tokens):
            statements.extend(_split_sql_statements(tokens[index + 1]))
            index += 2
            continue
        matched_option = next(
            (
                prefix
                for prefix in (
                    "--command=", "--execute=", "--init-command=", "--init-command-add="
                )
                if lowered.startswith(prefix)
            ),
            None,
        )
        if matched_option:
            statements.extend(_split_sql_statements(token[len(matched_option) :]))
        elif len(token) > 2 and lowered[:2] in {"-c", "-e"}:
            statements.extend(_split_sql_statements(token[2:]))
        index += 1
    if not statements and client == "sqlite3":
        sql_prefix = re.compile(r"^\s*(?:select|insert|update|delete|alter|drop|truncate|create)\b", re.IGNORECASE)
        for token in tokens[1:]:
            if sql_prefix.search(token):
                statements.extend(_split_sql_statements(token))
    return statements


def _database_client_input_files(action: str) -> list[str]:
    """Return SQL input files that a supported client would execute."""
    tokens = _tokens(action)
    client = _command_name(tokens)
    value_options = {
        "psql": {"-f", "--file"},
        "sqlcmd": {"-i"},
        "sqlite3": {"-init"},
        "mysql": set(),
    }
    equals_options = {
        "psql": ("--file=",),
        "sqlcmd": (),
        "sqlite3": ("--init=",),
        "mysql": (),
    }
    if client not in value_options:
        return []
    inputs: list[str] = []
    for index, token in enumerate(tokens):
        if token in value_options[client] and index + 1 < len(tokens):
            inputs.append(tokens[index + 1])
            continue
        lowered = token.lower()
        matched = next((prefix for prefix in equals_options[client] if lowered.startswith(prefix)), None)
        if matched:
            inputs.append(token[len(matched) :] or "the requested SQL input file")
        elif client == "psql" and len(token) > 2 and lowered.startswith("-f"):
            inputs.append(token[2:])
        elif client == "sqlcmd" and len(token) > 2 and lowered.startswith("-i"):
            inputs.append(token[2:])
    return _unique(inputs)


def _database_input_result(target: str) -> dict[str, Any]:
    return _result(
        "database",
        "HIGH",
        "REVIEW_FIRST",
        f"This database client executes SQL loaded from `{target}`, whose statements are not visible in the approval request.",
        ["The hidden SQL may change or delete persistent data, alter schema, change privileges, or invoke stored code."],
        "Reversibility cannot be determined without reviewing the complete input file and target database transaction behavior.",
        [f"Open and review `{target}` as inert text, identify the target database, and analyze each statement before executing the file."],
        [f"The contents of `{target}` and the connected database environment are not shown."],
        ["database_client_input", "hidden_sql", "database_write_unknown"],
    )


def _database_client_output_target(action: str) -> str | None:
    tokens = _tokens(action)
    client = _command_name(tokens)
    value_options = {
        "psql": {"-o", "--output"},
        "mysql": {"-T", "--tee"},
        "sqlcmd": {"-o"},
        "sqlite3": {"-cmd"},
    }
    equals_options = {
        "psql": ("--output=",),
        "mysql": ("--tee=",),
        "sqlcmd": (),
        "sqlite3": (),
    }
    if client not in value_options:
        return None
    for index, token in enumerate(tokens):
        if token in value_options[client] and index + 1 < len(tokens):
            value = tokens[index + 1]
            if client == "sqlite3" and token == "-cmd":
                match = re.match(r"\.(?:output|once)\s+(.+)", value, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
                continue
            return value
        lowered = token.lower()
        for prefix in equals_options[client]:
            if lowered.startswith(prefix):
                return token[len(prefix) :] or "the requested output file"
        if client in {"psql", "sqlcmd"} and len(token) > 2 and token[:2].lower() == "-o":
            return token[2:]
        if client == "mysql" and len(token) > 2 and token[:2] == "-T":
            return token[2:]
        if client == "sqlite3":
            match = re.match(r"\.(?:output|once)\s+(.+)", token, re.IGNORECASE)
            if match:
                return match.group(1).strip()
    return None


def _database_output_result(target: str) -> dict[str, Any]:
    return _result(
        "filesystem",
        "MODERATE",
        "REVIEW_FIRST",
        f"This writes database-client output to `{target}` instead of only displaying it.",
        [f"`{target}` may be created or its existing contents may be replaced."],
        "Restoring an overwritten output file requires version control, editor history, or a backup.",
        [f"Display a limited result first, then write it to a new confirmed path instead of `{target}` if a file is required."],
        [f"The action does not show whether `{target}` already contains unique or sensitive data."],
        ["database_client_output", "filesystem_write", "possible_overwrite"],
    )


def _database_statement_fallback(statement: str) -> dict[str, Any]:
    """Conservatively classify client statements outside the supported SQL subset."""
    stripped = statement.strip()
    shell_match = re.match(
        r"^(?:\\!|!|\\system\b|system\b)\s*(.*)$",
        stripped,
        re.IGNORECASE | re.DOTALL,
    )
    if shell_match:
        embedded = shell_match.group(1).strip()
        context = _result(
            "database",
            "HIGH",
            "REVIEW_FIRST",
            "This database-client statement invokes an external shell command.",
            ["The external command can change files, services, credentials, or other resources available to the current user."],
            "Recovery depends entirely on the embedded command.",
            ["Remove the database-client shell escape and review the external command as a separate explicit action."],
            [],
            ["database_client_shell", "embedded_code", "arbitrary_execution"],
        )
        if embedded:
            return _combine_analyses(
                [context, analyze_action(embedded)],
                ["database-client shell escape", embedded],
                "This database-client shell action",
            )
        return context

    output_match = re.match(r"^(?:\\o|\\out)\s+(.+)$", stripped, re.IGNORECASE | re.DOTALL)
    if output_match:
        return _database_output_result(output_match.group(1).strip())

    meta_match = re.match(r"^(\\[A-Za-z]+|\.[A-Za-z]+)\b", stripped)
    if meta_match:
        return _result(
            "database",
            "HIGH",
            "REVIEW_FIRST",
            f"This database client uses the `{meta_match.group(1)}` meta-command, which is not proven read-only by the v0.1 rules.",
            ["It may execute hidden SQL, read or write files, load code, or change the connected database."],
            "Reversibility depends on the hidden input, target database, and affected files.",
            ["Inspect the meta-command and any referenced input separately, or use a plain limited SELECT for read-only inspection."],
            ["The analyzer cannot see hidden input or client state referenced by this meta-command."],
            ["database_client_meta", "database_write_unknown"],
        )

    keyword_match = re.match(r"^([A-Za-z]+)\b", stripped)
    keyword = keyword_match.group(1).lower() if keyword_match else "unrecognized"
    privilege_change = keyword in {"grant", "revoke"}
    execution_statement = keyword in {"call", "do", "exec", "execute"}
    return _result(
        "database",
        "HIGH" if privilege_change or execution_statement else "MODERATE",
        "REVIEW_FIRST",
        (
            f"This `{keyword.upper()}` statement changes database privileges."
            if privilege_change
            else f"This `{keyword.upper()}` database statement is outside the analyzer's proven read-only SQL subset."
        ),
        (
            ["Database users or roles may gain or lose access to shared data and operations."]
            if privilege_change
            else ["The statement may change persistent database state, invoke stored code, acquire locks, or write files."]
        ),
        "Reversibility depends on the exact database statement, transaction state, and target environment.",
        ["Review this statement separately against the target database and use a documented read-only equivalent when inspection is the goal."],
        ["The analyzer does not have a specific semantic rule for this database statement."],
        ["sql_privilege_change" if privilege_change else "unsupported_database_statement", "database_write_unknown"],
    )


def _sqlite_meta_analysis(action: str) -> dict[str, Any] | None:
    tokens = _tokens(action)
    if _command_name(tokens) != "sqlite3":
        return None
    safe_meta = {
        ".databases", ".dbconfig", ".headers", ".help", ".indexes", ".schema",
        ".show", ".tables", ".timeout", ".version", ".vfsinfo", ".vfslist",
    }
    for token in tokens[1:]:
        stripped = token.strip()
        if not stripped.startswith("."):
            continue
        command, _, argument = stripped.partition(" ")
        lowered = command.lower()
        if lowered in {".shell", ".system"}:
            embedded = argument.strip()
            context = _result(
                "database",
                "HIGH",
                "REVIEW_FIRST",
                f"This SQLite client action invokes `{lowered}`, which runs an external shell command.",
                ["The external command can change any files or services available to the current user."],
                "Recovery depends entirely on the external command.",
                ["Remove the SQLite shell meta-command and review the external action separately."],
                [],
                ["sqlite_shell", "embedded_code", "arbitrary_execution"],
            )
            if embedded:
                return _combine_analyses(
                    [context, analyze_action(embedded)],
                    [lowered, embedded],
                    "This SQLite shell action",
                )
            return context
        if lowered in {".output", ".once"}:
            continue
        if lowered not in safe_meta:
            return _result(
                "database",
                "HIGH" if lowered in {".load", ".read", ".restore", ".import"} else "MODERATE",
                "REVIEW_FIRST",
                f"This SQLite client uses the `{lowered}` meta-command, which is not proven read-only by the v0.1 rules.",
                ["It may load code, execute hidden SQL, change the database, or create or restore files."],
                "Reversibility depends on the hidden input and target database or files.",
                ["Inspect the meta-command and its input separately, or use a plain SELECT for read-only inspection."],
                ["The analyzer cannot see the contents of files or extensions referenced by this meta-command."],
                ["sqlite_meta_command", "database_write_unknown"],
            )
    return None


def _split_top_level_detailed(action: str) -> tuple[list[str], list[str]]:
    """Split shell-like compound text and retain inert top-level separators."""
    parts: list[str] = []
    separators: list[str] = []
    start = 0
    quote: str | None = None
    in_backtick = False
    escaped = False
    substitution_depth = 0
    index = 0

    while index < len(action):
        char = action[index]
        next_char = action[index + 1] if index + 1 < len(action) else ""

        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if char == "`" and quote != "'":
            in_backtick = not in_backtick
            index += 1
            continue
        if in_backtick:
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"'):
            quote = char
            index += 1
            continue
        if char in {"$", "<", ">", "="} and next_char == "(":
            substitution_depth += 1
            index += 2
            continue
        if char == ")" and substitution_depth:
            substitution_depth -= 1
            index += 1
            continue

        separator = ""
        if substitution_depth == 0:
            if action[index : index + 2] in ("&&", "||", "|&"):
                separator = action[index : index + 2]
            elif char in (";", "\n", "|"):
                separator = char
            elif char == "&" and next_char != ">" and (index == 0 or action[index - 1] != ">"):
                separator = char

        if separator:
            part = action[start:index].strip()
            if part:
                parts.append(part)
                separators.append(separator)
            index += len(separator)
            start = index
            continue
        index += 1

    tail = action[start:].strip()
    if tail:
        parts.append(tail)
    if len(separators) >= len(parts):
        separators = separators[: max(0, len(parts) - 1)]
    return parts, separators


def _split_top_level(action: str) -> list[str]:
    """Split shell-like compound text without interpreting or executing it."""
    return _split_top_level_detailed(action)[0]


def _extract_substitutions(segment: str) -> tuple[list[str], str]:
    """Extract command-substitution bodies as data and return a scrubbed outer action."""
    substitutions: list[str] = []
    output: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0

    while index < len(segment):
        char = segment[index]
        next_char = segment[index + 1] if index + 1 < len(segment) else ""
        if escaped:
            output.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            output.append(char)
            escaped = True
            index += 1
            continue
        if quote == "'":
            output.append(char)
            if char == "'":
                quote = None
            index += 1
            continue
        if char == "'" and quote is None:
            quote = "'"
            output.append(char)
            index += 1
            continue
        if char == "`" and quote != "'":
            body_start = index + 1
            cursor = body_start
            inner_escaped = False
            while cursor < len(segment):
                current = segment[cursor]
                if inner_escaped:
                    inner_escaped = False
                elif current == "\\":
                    inner_escaped = True
                elif current == "`":
                    break
                cursor += 1
            if cursor < len(segment) and segment[cursor] == "`":
                substitutions.append(segment[body_start:cursor])
                output.append(" __COMMAND_SUBSTITUTION__ ")
                index = cursor + 1
                continue
        if char == '"':
            quote = None if quote == '"' else '"'
            output.append(char)
            index += 1
            continue
        if char in {"$", "<", ">", "="} and next_char == "(":
            body_start = index + 2
            cursor = body_start
            depth = 1
            inner_quote: str | None = None
            inner_escaped = False
            while cursor < len(segment) and depth:
                current = segment[cursor]
                following = segment[cursor + 1] if cursor + 1 < len(segment) else ""
                if inner_escaped:
                    inner_escaped = False
                elif current == "\\" and inner_quote != "'":
                    inner_escaped = True
                elif inner_quote:
                    if current == inner_quote:
                        inner_quote = None
                elif current in ("'", '"'):
                    inner_quote = current
                elif current in {"$", "<", ">", "="} and following == "(":
                    depth += 1
                    cursor += 1
                elif current == ")":
                    depth -= 1
                    if depth == 0:
                        break
                cursor += 1
            if depth == 0:
                substitutions.append(segment[body_start:cursor])
                output.append(" __COMMAND_SUBSTITUTION__ ")
                index = cursor + 1
                continue
        output.append(char)
        index += 1

    return substitutions, "".join(output).strip()


def _execution_order(action: str) -> list[str]:
    ordered: list[str] = []
    for segment in _split_top_level(action):
        substitutions, outer = _extract_substitutions(segment)
        for substitution in substitutions:
            ordered.extend(_execution_order(substitution))
        if outer:
            ordered.append(outer)
    return ordered


def _secret_pipeline_transfer(action: str) -> dict[str, Any] | None:
    parts, separators = _split_top_level_detailed(action)
    secret_output_seen = False
    for index, part in enumerate(parts):
        if index and separators[index - 1] not in {"|", "|&"}:
            secret_output_seen = False
        secret_analysis = _analyze_secrets(part)
        part_tokens = _tokens(part)
        raw_command = (
            part_tokens[0].replace("\\", "/").rsplit("/", 1)[-1].lower()
            if part_tokens
            else ""
        )
        if secret_analysis is not None or raw_command in {"env", "printenv", "set", "export"}:
            secret_output_seen = True
        command = _command_name(part_tokens)
        if index and separators[index - 1] in {"|", "|&"} and secret_output_seen and command in NETWORK_TRANSFER_COMMANDS:
            return _result(
                "secrets",
                "CRITICAL",
                "DO_NOT_APPROVE",
                "This pipeline reads credential-bearing content and sends its output to a network-transfer command.",
                ["A secret may leave this computer and become available to the remote destination."],
                "Transmission cannot be undone; exposed credentials usually need to be revoked and replaced.",
                ["Do not pipe credential output to the network. Remove the secret and verify exactly what non-sensitive data is required."],
                ["The destination's ownership and data-retention behavior are not established by this action."],
                ["compound_action", "secret_reference", "credential_exfiltration", "network_transfer"],
            )
    return None


def _has_secret_marker(action: str) -> bool:
    tokens = _tokens(action)
    command = _command_name(tokens)
    path_sensitive_commands = {
        "cat", "less", "more", "head", "tail", "grep", "egrep", "fgrep", "sed", "awk",
        "jq", "base64", "xxd", "strings", "type", "get-content", "git", "curl", "wget",
        "scp", "sftp", "rsync", "rm", "unlink", "del", "remove-item", "vi", "vim", "nano",
        "code", "tee", "set-content",
    }
    normalized_secret_path = command in path_sensitive_commands and any(
        SECRET_FILE_RE.search(variant)
        or SECRET_MOUNT_RE.search(variant)
        or (":" in variant and SECRET_FILE_RE.search(variant.rsplit(":", 1)[-1]))
        for token in tokens[1:]
        for variant in _possible_expanded_tokens(token)
    )
    secret_projection = bool(
        re.match(r"^\s*select\b", action, re.IGNORECASE)
        and re.search(
            r"\bselect\b[\s\S]*?\b" + SECRET_FIELD_PATTERN + r"\b[\s\S]*?\bfrom\b",
            action,
            re.IGNORECASE,
        )
    )
    return bool(
        SECRET_FILE_RE.search(action)
        or SECRET_MOUNT_RE.search(action)
        or SECRET_VAR_RE.search(action)
        or SECRET_ENVIRONMENT_GETTER_RE.search(action)
        or normalized_secret_path
        or secret_projection
        or re.search(
            r"\b(?:aws\s+configure\s+get\s+aws_(?:secret_access_key|access_key_id|session_token)|"
            r"gcloud\s+auth\s+print-(?:access|identity)-token|gh\s+auth\s+token|"
            r"security\s+find-(?:generic|internet)-password\b[^;&|]*(?:\s-w\b|--show-password)|"
            r"(?:op\s+read|pass\s+show|vault\s+kv\s+get)\b)",
            action,
            re.IGNORECASE,
        )
    )


def _analyze_secrets(action: str) -> dict[str, Any] | None:
    tokens = _tokens(action)
    command = _command_name(tokens)
    named_secret_output = command == "printenv" and any(
        SECRET_NAME_RE.fullmatch(token.strip("${}")) for token in tokens[1:]
    )
    if not (_has_secret_marker(action) or named_secret_output):
        return None

    lowered = action.lower()
    git_secret_output = command == "git" and bool(re.search(r"\bgit\b[\s\S]*?\b(?:show|diff)\b", lowered))
    sql_secret_output = bool(
        re.match(r"^\s*select\b", action, re.IGNORECASE)
        and re.search(
            r"\bselect\b[\s\S]*?\b" + SECRET_FIELD_PATTERN + r"\b[\s\S]*?\bfrom\b",
            action,
            re.IGNORECASE,
        )
    )
    transmit = command in NETWORK_TRANSFER_COMMANDS
    stage = command == "git" and bool(re.search(r"\bgit\s+(?:add|commit)\b", lowered))
    print_value = command in {
        "cat", "echo", "printf", "printenv", "env", "type", "get-content", "write-output", "write-host",
        "less", "more", "head", "tail", "grep", "egrep", "fgrep", "sed", "awk", "jq", "base64", "xxd", "strings",
    } or git_secret_output or sql_secret_output or bool(SECRET_ENVIRONMENT_GETTER_RE.search(action)) or bool(
        re.search(
            r"\b(?:aws\s+configure\s+get|gcloud\s+auth\s+print-|gh\s+auth\s+token|"
            r"security\s+find-|op\s+read|pass\s+show|vault\s+kv\s+get)\b",
            lowered,
        )
    )
    delete = command in {"rm", "unlink", "del", "remove-item"}
    edit = command in {"sed", "tee", "vi", "vim", "nano", "code", "set-content"} or bool(
        re.search(r">>?\s*[^\s]*?(?:\.env|credentials|id_rsa)", lowered)
    )

    if transmit:
        return _result(
            "secrets",
            "CRITICAL",
            "DO_NOT_APPROVE",
            "This sends a value or file that appears to contain credentials to another location.",
            ["A secret could leave this computer and be used by someone else."],
            "Transmission cannot be undone; exposed credentials usually need to be revoked and replaced.",
            ["Remove the credential from the request and verify exactly what data must be sent."],
            ["The destination's ownership and data-retention behavior are not established by this action."],
            ["secret_reference", "credential_exfiltration", "network_transfer"],
        )
    if stage:
        staged_target = ".env" if re.search(r"(?:^|[\s/])\.env(?:[\s/]|$)", action) else "the credential-bearing file"
        return _result(
            "secrets",
            "HIGH",
            "REVIEW_FIRST",
            f"This adds `{staged_target}` to Git's staging area—the list of file changes prepared for the next commit.",
            [f"A later commit could copy the secret from `{staged_target}` into repository history, where it may be shared remotely."],
            "It can be removed from the staging area before commit. After commit or push, cleanup may require rewriting history and replacing the credential.",
            [f"Keep `{staged_target}` out of version control, add it to `.gitignore`, and commit only a placeholder example without real credentials."],
            [],
            ["secret_reference", "secret_staged"],
        )
    if print_value:
        return _result(
            "secrets",
            "HIGH",
            "REVIEW_FIRST",
            "This prints content that may contain a credential.",
            ["The credential could appear in terminal history, logs, recordings, or copied output."],
            "Printed output may persist in logs; if exposed, the credential may need replacement.",
            ["Inspect only non-sensitive key names or use a tool that redacts secret values."],
            [],
            ["secret_reference", "secret_output"],
        )
    if delete:
        return _result(
            "secrets",
            "HIGH",
            "REVIEW_FIRST",
            "This deletes a file that may contain credentials.",
            ["Local access to services may stop working and the credential file may be difficult to reconstruct."],
            "Recovery depends on a secure backup or the ability to issue replacement credentials.",
            ["Confirm the target and preserve a secure backup before deleting it."],
            ["The action does not show whether a secure backup or replacement process exists."],
            ["secret_reference", "credential_deletion"],
        )
    if edit:
        return _result(
            "secrets",
            "HIGH",
            "REVIEW_FIRST",
            "This creates or changes a file that may contain credentials.",
            ["Applications may gain or lose access, and a secret could be accidentally stored in an unsafe place."],
            "The file change may be reversible if a secure previous version exists; credential changes themselves may not be.",
            ["Review the exact file diff without printing secret values and keep the file outside version control."],
            ["The action does not establish whether a secure previous version exists."],
            ["secret_reference", "credential_modification"],
        )
    return _result(
        "secrets",
        "MODERATE",
        "REVIEW_FIRST",
        "This references a file or variable that may contain credentials.",
        ["A later step could expose or modify sensitive access information."],
        "No direct change is visible, but the sensitivity of the referenced data requires care.",
        ["Confirm that the operation uses only the minimum required non-secret information."],
        ["The action alone does not show whether the referenced value is populated or sensitive."],
        ["secret_reference"],
    )


def _analyze_database(action: str) -> dict[str, Any] | None:
    sqlite_meta = _sqlite_meta_analysis(action)
    if sqlite_meta is not None:
        return sqlite_meta
    production = bool(PRODUCTION_RE.search(action))
    output_target = _database_client_output_target(action)
    client_statements = _database_client_statements(action)
    input_files = _database_client_input_files(action)
    if client_statements or input_files:
        contextual_statements = [
            statement + (" -- production" if production else "")
            for statement in client_statements
        ]
        analyses = [_database_input_result(target) for target in input_files]
        sub_actions = [f"execute SQL input file {target}" for target in input_files]
        for statement in contextual_statements:
            analysis = _analyze_secrets(statement) or _analyze_database(statement)
            analyses.append(analysis if analysis is not None else _database_statement_fallback(statement))
            sub_actions.append(statement.removesuffix(" -- production"))
        if output_target is not None:
            analyses.append(_database_output_result(output_target))
            sub_actions.append(f"write database output to {output_target}")
        if len(analyses) == 1:
            return analyses[0]
        if analyses:
            return _combine_analyses(
                analyses,
                sub_actions,
                "This database-client action",
            )
    if output_target is not None:
        return _database_output_result(output_target)

    analysis_action = _expand_mysql_executable_comments(action)
    lowered = _mask_sql_literals(analysis_action).lower().strip()
    command = _command_name(_tokens(action))
    direct_sql = bool(re.match(r"^(?:select|insert|update|delete|alter|drop|truncate|create)\b", lowered))
    database_client = command in {"psql", "mysql", "sqlite3", "sqlcmd"}
    sql_match = (
        re.search(r"\b(select|insert|update|delete|alter|drop|truncate|create)\b", lowered)
        if direct_sql or database_client
        else None
    )
    migration = bool(
        re.search(
            r"\b(?:alembic\s+(?:upgrade|downgrade)|prisma\s+migrate|"
            r"django-admin\s+migrate|manage\.py\s+migrate|rails\s+db:migrate|"
            r"sequelize\s+db:migrate|knex\s+migrate)",
            lowered,
        )
    )
    if not (sql_match or migration or database_client):
        return None

    uncertainties = (
        []
        if production
        else ["The action does not show whether the connected database is local, staging, or production."]
    )
    operation = sql_match.group(1) if sql_match else "migration"
    target = _sql_target(analysis_action, operation)

    if operation == "select":
        side_effect_function = next(
            (
                name
                for name in sorted(SQL_DESTRUCTIVE_SELECT_FUNCTIONS | SQL_MUTATING_SELECT_FUNCTIONS)
                if re.search(rf"\b{re.escape(name)}\s*\(", lowered)
            ),
            None,
        )
        if side_effect_function:
            destructive = side_effect_function in SQL_DESTRUCTIVE_SELECT_FUNCTIONS
            return _result(
                "database",
                "HIGH" if destructive else "MODERATE",
                "REVIEW_FIRST",
                f"This SELECT invokes `{side_effect_function}`, a database function with side effects rather than a read-only query.",
                [
                    "It may delete a database object or terminate another database session."
                    if destructive
                    else "It may advance stored sequence state, acquire a lock, send a notification, or change database session state."
                ],
                "Recovery depends on the function; deleted objects or terminated work may not have a simple undo.",
                ["Review the function separately, confirm the target database, and use a read-only query that does not invoke it when possible."],
                uncertainties,
                ["sql_select", "sql_function_side_effect", "database_write"]
                + (["destructive_database"] if destructive else []),
            )
        function_calls = {
            match.group(1).lower().rsplit(".", 1)[-1]
            for match in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_.]*)\s*\(", lowered)
        }
        sql_syntax_words = {"in", "exists", "from", "where", "select", "case", "cast"}
        unknown_functions = sorted(function_calls - SQL_READ_ONLY_FUNCTIONS - sql_syntax_words)
        if unknown_functions:
            return _result(
                "database",
                "MODERATE",
                "REVIEW_FIRST",
                f"This SELECT invokes `{unknown_functions[0]}`, whose side effects are not proven read-only by the v0.1 rules.",
                ["The function may read data, change database state, acquire locks, or call an extension."],
                "Reversibility cannot be determined without the function definition and target database context.",
                ["Inspect the function definition or replace it with a plain SELECT from explicit tables before approving it."],
                uncertainties + ["The analyzer does not know whether this database function is pure or side-effectful."],
                ["sql_select", "sql_function_unknown", "database_write_unknown"],
            )
        select_write = bool(
            re.search(
                r"\binto\b|\bfor\s+(?:update|share|no\s+key\s+update|key\s+share)\b|"
                r"\block\s+in\s+share\s+mode\b|\bwith\s*\([^)]*\b(?:updlock|xlock|holdlock|tablockx)\b",
                lowered,
            )
        )
        if select_write:
            return _result(
                "database",
                "MODERATE",
                "REVIEW_FIRST",
                f"This SELECT reads from `{target}` but also requests a write-like result or row lock.",
                ["It may create an output table or file, or hold locks that block other database changes."],
                "Created output needs deliberate cleanup; locks normally end with the transaction or connection.",
                ["Run a plain limited SELECT first, then review the INTO or locking clause and its destination separately."],
                uncertainties,
                ["sql_select", "sql_select_write", "database_write"],
            )
        return _result(
            "database",
            "LOW",
            "SAFE_TO_APPROVE",
            f"This reads rows from `{target}` without changing them.",
            [f"Data from `{target}` may be displayed in the command output."],
            "No database change needs to be undone.",
            ["Limit selected columns or rows if the result may contain sensitive data."],
            uncertainties if database_client else [],
            ["sql_select", "read_only"],
        )

    if operation in ("drop", "truncate"):
        risk = "CRITICAL" if production else "HIGH"
        recommendation = "DO_NOT_APPROVE" if production else "REVIEW_FIRST"
        environment = "production " if production else ""
        summary = (
            f"This permanently removes the {environment}database table or object `{target}`."
            if operation == "drop"
            else f"This removes every row from the {environment}table `{target}` while leaving its table structure in place."
        )
        return _result(
            "database",
            risk,
            recommendation,
            summary,
            [f"Stored data{' and its structure' if operation == 'drop' else ''} in `{target}` may be removed."],
            "Recovery normally requires a verified backup or a database-specific recovery mechanism.",
            ["Verify the database target, take a tested backup, and preview the affected object before continuing."],
            uncertainties,
            [f"sql_{operation}", "destructive_database"] + (["production_known"] if production else []),
        )

    if operation in ("update", "delete"):
        has_where = bool(re.search(r"\bwhere\b", lowered))
        risk = "CRITICAL" if production and not has_where else "HIGH" if not has_where or production else "MODERATE"
        recommendation = "DO_NOT_APPROVE" if risk == "CRITICAL" else "REVIEW_FIRST"
        where_clause = _sql_clause(analysis_action, "where")
        set_clause = _sql_clause(analysis_action, "set") if operation == "update" else ""
        if operation == "update":
            scope = (
                f"every row in `{target}` by setting `{set_clause}`; no row limit is present"
                if not has_where
                else f"rows in `{target}` where `{where_clause}`, setting `{set_clause}`"
            )
        else:
            scope = (
                f"every row from `{target}`; no row limit is present"
                if not has_where
                else f"rows from `{target}` where `{where_clause}`"
            )
        safer = (
            f"Add a narrow WHERE condition, then run a SELECT against `{target}` to preview the rows before changing them."
            if not has_where
            else f"Run a SELECT from `{target}` with the same condition (`{where_clause}`) and use a transaction with a rollback plan."
        )
        return _result(
            "database",
            risk,
            recommendation,
            f"This {operation.upper()} operation changes {scope}.",
            [f"Persistent records in `{target}` may be {'changed' if operation == 'update' else 'removed'}."],
            "A transaction can be rolled back before commit; afterward, recovery may require a backup or compensating update.",
            [safer],
            uncertainties,
            [f"sql_{operation}", "unbounded_sql" if not has_where else "bounded_sql"]
            + (["production_known"] if production else []),
        )

    if operation == "alter":
        risk = "CRITICAL" if production and re.search(r"\bdrop\b", lowered) else "HIGH"
        return _result(
            "database",
            risk,
            "DO_NOT_APPROVE" if risk == "CRITICAL" else "REVIEW_FIRST",
            f"This changes the structure of {'the production ' if production else ''}table `{target}`; the visible statement may add, change, or remove columns or rules.",
            [f"The shape of `{target}` and applications that use it may change."],
            "Some schema changes can be reversed with another migration, but data removed by a schema change may require a backup.",
            ["Review a generated migration plan and test it against a disposable copy first."],
            uncertainties,
            ["sql_alter", "schema_change"] + (["production_known"] if production else []),
        )

    if operation == "migration":
        return _result(
            "database",
            "HIGH",
            "REVIEW_FIRST",
            "This applies pending Alembic migration steps, which are instructions that change the database's table structure and may also transform stored data.",
            ["The connected database's tables, columns, and possibly stored records may change."],
            "Reversal depends on whether matching downgrade steps exist and preserve data; this command itself only applies upgrades.",
            ["Preview the exact database statements, inspect each pending migration step, and confirm the target database before running it."],
            uncertainties,
            ["database_migration"] + (["production_known"] if production else []),
        )

    return _result(
        "database",
        "MODERATE",
        "REVIEW_FIRST",
        f"This {operation.upper()} operation writes to `{target}` in the connected database.",
        [f"Persistent data or structure in `{target}` may be added or changed."],
        "It may be reversible with a transaction or a deliberate cleanup operation.",
        ["Confirm the target database and review the exact rows or schema to be created."],
        uncertainties,
        [f"sql_{operation}", "database_write"],
    )


def _git_subcommand(action: str) -> str | None:
    tokens = _tokens(action)
    if _command_name(tokens) != "git":
        return None
    try:
        index = next(
            i
            for i, token in enumerate(tokens)
            if token.replace("\\", "/").rsplit("/", 1)[-1].lower() == "git"
        ) + 1
    except StopIteration:
        return None
    global_options_with_values = {
        "-c", "-C", "--git-dir", "--work-tree", "--namespace", "--config-env", "--exec-path"
    }
    while index < len(tokens):
        token = tokens[index]
        lowered = token.lower()
        if token in global_options_with_values:
            index += 2
            continue
        if lowered.startswith(("--git-dir=", "--work-tree=", "--namespace=", "--config-env=", "--exec-path=")):
            index += 1
            continue
        if (token.startswith("-C") or token.startswith("-c")) and len(token) > 2:
            index += 1
            continue
        if token == "--":
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return lowered
    return None


def _git_operation(action: str) -> str | None:
    subcommand = _git_subcommand(action)
    if subcommand is None:
        return None
    return subcommand if subcommand in GIT_RECOGNIZED_OPERATIONS else "git"


def _git_shell_alias(action: str) -> tuple[str, str] | None:
    tokens = _tokens(action)
    invoked = _git_subcommand(action)
    if invoked is None or invoked in GIT_BUILTIN_COMMANDS:
        return None
    configurations: list[str] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "-c" and index + 1 < len(tokens):
            configurations.append(tokens[index + 1])
            index += 2
            continue
        if token.startswith("-c") and len(token) > 2:
            configurations.append(token[2:])
        index += 1
    for configuration in configurations:
        match = re.match(r"alias\.([^=]+)=(.*)", configuration, re.IGNORECASE | re.DOTALL)
        if not match or match.group(1) != invoked:
            continue
        expansion = match.group(2).lstrip()
        if expansion.startswith("!"):
            return invoked, expansion[1:].strip()
    return None


def _git_execution_payload(action: str) -> tuple[str, str] | None:
    tokens = _tokens(action)
    execution_config_patterns = (
        r"core\.(?:sshcommand|gitproxy|pager|fsmonitor)",
        r"core\.editor|sequence\.editor|gpg\.program",
        r"pager\..+",
        r"diff\.(?:external|[^.]+\.(?:command|textconv))",
        r"filter\.[^.]+\.(?:clean|smudge|process)",
        r"credential\.[^.]+\.helper|credential\.helper",
        r".*\.(?:command|program|helper)",
    )
    execution_environment = {
        "GIT_SSH", "GIT_SSH_COMMAND", "GIT_PROXY_COMMAND", "GIT_EXTERNAL_DIFF",
        "GIT_PAGER", "PAGER", "GIT_EDITOR", "GIT_ASKPASS", "SSH_ASKPASS",
    }
    assignments: dict[str, str] = {}
    for token in tokens:
        if "=" not in token or not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", token):
            continue
        key, value = token.split("=", 1)
        assignments[key.upper()] = value
        if key.upper() in execution_environment:
            return key, value
    try:
        config_count = int(assignments.get("GIT_CONFIG_COUNT", "0"))
    except ValueError:
        config_count = 0
    for config_index in range(max(0, min(config_count, 32))):
        key = assignments.get(f"GIT_CONFIG_KEY_{config_index}", "")
        value = assignments.get(f"GIT_CONFIG_VALUE_{config_index}", "")
        if key and any(re.fullmatch(pattern, key, re.IGNORECASE) for pattern in execution_config_patterns):
            return key, value.lstrip("!").strip()
    for index, token in enumerate(tokens):
        config_env = ""
        if token == "--config-env" and index + 1 < len(tokens):
            config_env = tokens[index + 1]
        elif token.startswith("--config-env="):
            config_env = token.split("=", 1)[1]
        if "=" not in config_env:
            continue
        key, variable = config_env.split("=", 1)
        if any(re.fullmatch(pattern, key, re.IGNORECASE) for pattern in execution_config_patterns):
            return key, assignments.get(variable.upper(), "the environment-supplied external command")
    index = 0
    while index < len(tokens):
        token = tokens[index]
        configuration = ""
        if token == "-c" and index + 1 < len(tokens):
            configuration = tokens[index + 1]
            index += 2
        elif token.startswith("-c") and len(token) > 2:
            configuration = token[2:]
            index += 1
        else:
            index += 1
        if configuration and "=" in configuration:
            key, value = configuration.split("=", 1)
            if any(re.fullmatch(pattern, key, re.IGNORECASE) for pattern in execution_config_patterns):
                return key, value.lstrip("!").strip()

    command_options = {
        "--upload-pack", "--receive-pack", "--exec", "--git-upload-pack", "--git-receive-pack"
    }
    for index, token in enumerate(tokens):
        lowered = token.lower()
        if lowered in command_options and index + 1 < len(tokens):
            return lowered, tokens[index + 1]
        for option in command_options:
            prefix = option + "="
            if lowered.startswith(prefix):
                return option, token[len(prefix) :]
        if lowered.startswith("ext::"):
            return "ext:: transport", token[5:]
    return None


def _git_push_destination(action: str) -> tuple[str, str]:
    tokens = _tokens(action)
    try:
        index = next(i for i, token in enumerate(tokens) if token.lower() == "push")
    except StopIteration:
        return "the configured remote", "the selected branch"
    positional: list[str] = []
    push_options_with_values = {"-o", "--push-option", "--repo", "--receive-pack", "--exec"}
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        lowered = token.lower()
        if lowered in push_options_with_values:
            cursor += 2
            continue
        if lowered.startswith(("--push-option=", "--repo=", "--receive-pack=", "--exec=")):
            cursor += 1
            continue
        if token.startswith("-"):
            cursor += 1
            continue
        positional.append(token)
        cursor += 1
    remote = positional[0] if positional else "the configured remote"
    branch = positional[1] if len(positional) > 1 else "the selected branch"
    return remote, branch


def _git_output_target(action: str) -> str | None:
    tokens = _tokens(action)
    for index, token in enumerate(tokens):
        lowered = token.lower()
        if lowered == "--output" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token == "-o" and index + 1 < len(tokens):
            return tokens[index + 1]
        if lowered.startswith("--output="):
            return token.split("=", 1)[1] or "the requested output file"
        if token.startswith("-o") and len(token) > 2:
            return token[2:]
    return None


def _git_read_options_are_safe(action: str, operation: str) -> bool:
    tokens = _tokens(action)
    try:
        index = next(i for i, token in enumerate(tokens) if token.lower() == operation)
    except StopIteration:
        return False
    allowed_exact = {
        "status": {
            "-s", "--short", "-b", "--branch", "--long", "-v", "--verbose", "-z",
            "--show-stash", "--ahead-behind", "--no-ahead-behind", "--renames", "--no-renames",
        },
        "diff": {
            "-p", "--patch", "--cached", "--staged", "--stat", "--numstat", "--shortstat",
            "--name-only", "--name-status", "--check", "--summary", "--color", "--no-color",
            "--no-renames", "--no-index", "--exit-code", "--quiet", "--binary", "--full-index",
        },
        "log": {
            "--oneline", "--stat", "--shortstat", "--name-only", "--name-status", "--graph",
            "--no-decorate", "--all", "--abbrev-commit", "--reverse", "--first-parent",
            "--merges", "--no-merges", "--follow", "-p", "--patch",
        },
        "show": {
            "--oneline", "--stat", "--shortstat", "--name-only", "--name-status", "--no-decorate",
            "--abbrev-commit", "-p", "--patch", "--no-patch",
        },
    }[operation]
    allowed_prefixes = {
        "status": (
            "--porcelain=", "--untracked-files=", "--ignored=", "--ignore-submodules=",
            "--column=", "--find-renames=",
        ),
        "diff": (
            "--unified=", "--word-diff=", "--find-renames=", "--relative=", "--submodule=",
            "--abbrev=", "--color=",
        ),
        "log": (
            "--max-count=", "--decorate=", "--branches=", "--tags=", "--remotes=", "--since=",
            "--until=", "--author=", "--grep=", "--format=", "--pretty=", "--date=",
        ),
        "show": ("--format=", "--pretty=", "--abbrev=", "--color="),
    }[operation]
    value_options = {"-n", "--max-count", "--format", "--pretty"} if operation in {"log", "show"} else set()
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token == "--":
            return True
        if token in value_options:
            cursor += 2
            continue
        if not token.startswith("-") or re.fullmatch(r"-\d+", token):
            cursor += 1
            continue
        if token in allowed_exact or token.startswith(allowed_prefixes):
            cursor += 1
            continue
        return False
    return True


def _git_fetch_options_are_safe(action: str) -> bool:
    tokens = _tokens(action)
    try:
        index = next(i for i, token in enumerate(tokens) if token.lower() == "fetch")
    except StopIteration:
        return False
    allowed = {
        "--dry-run", "--append", "--atomic", "--all", "--multiple", "--tags", "--no-tags",
        "--keep", "--unshallow", "--update-shallow", "--refetch", "--prefetch", "--negotiate-only",
        "--no-auto-gc", "--auto-maintenance", "--write-fetch-head", "--no-write-fetch-head",
        "--progress", "--no-progress", "--ipv4", "--ipv6", "-q", "--quiet", "-v", "--verbose",
    }
    value_options = {
        "--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--jobs", "-j",
        "--submodule-prefix", "--negotiation-tip", "--filter", "--server-option",
    }
    allowed_prefixes = (
        "--depth=", "--deepen=", "--shallow-since=", "--shallow-exclude=", "--jobs=",
        "--recurse-submodules=", "--negotiation-tip=", "--filter=", "--server-option=",
    )
    cursor = index + 1
    while cursor < len(tokens):
        token = tokens[cursor]
        if token in value_options:
            cursor += 2
            continue
        if token in {"--recurse-submodules", "--no-recurse-submodules"}:
            cursor += 1
            continue
        if token in allowed or token.startswith(allowed_prefixes) or not token.startswith("-"):
            cursor += 1
            continue
        return False
    return True


def _analyze_git(action: str) -> dict[str, Any] | None:
    shell_alias = _git_shell_alias(action)
    if shell_alias is not None:
        alias_name, embedded_action = shell_alias
        embedded_analysis = analyze_action(embedded_action)
        alias_context = _result(
            "git",
            "HIGH",
            "REVIEW_FIRST",
            f"This defines and invokes the temporary Git alias `{alias_name}`, which runs an embedded shell command.",
            ["The embedded command runs with the current user's access from the repository context."],
            "Recovery depends entirely on every operation in the embedded shell command.",
            ["Do not use a shell alias for approval; review and analyze the embedded command as a separate explicit action."],
            [],
            ["git_shell_alias", "embedded_code", "arbitrary_execution"],
        )
        return _combine_analyses(
            [alias_context, embedded_analysis],
            [f"invoke Git alias {alias_name}", embedded_action],
            "This Git shell-alias action",
        )
    execution_payload = _git_execution_payload(action)
    if execution_payload is not None:
        source, embedded_action = execution_payload
        embedded_analysis = analyze_action(embedded_action)
        execution_context = _result(
            "git",
            "HIGH",
            "REVIEW_FIRST",
            f"This Git action supplies `{source}`, which Git may execute as an external command.",
            ["The supplied command can access and change files, credentials, repository state, or remote resources as the current user."],
            "Recovery depends entirely on the supplied external command.",
            ["Remove the execution-bearing option and use Git's normal transport or built-in behavior; review the external command separately if it is truly required."],
            [],
            ["git_external_command", "embedded_code", "arbitrary_execution"],
        )
        return _combine_analyses(
            [execution_context, embedded_analysis],
            ["configure Git external command", embedded_action],
            "This Git external-command action",
        )
    operation = _git_operation(action)
    if operation is None:
        return None
    lowered = action.lower()
    output_target = _git_output_target(action)
    if operation in {"status", "diff", "log", "show"} and output_target is not None:
        return _result(
            "filesystem",
            "MODERATE",
            "REVIEW_FIRST",
            f"This writes Git {operation} output to `{output_target}` instead of only displaying it.",
            [f"`{output_target}` may be created or its existing contents may be replaced."],
            "Restoring an overwritten file requires version control, editor history, or a backup.",
            [f"Display the Git {operation} output first, then write it to a new confirmed path only if needed."],
            [f"The action does not show whether `{output_target}` already contains unique data."],
            [f"git_{operation}", "filesystem_write", "possible_overwrite"],
        )
    if operation in {"status", "diff", "log", "show"} and re.search(
        r"(?:^|\s)(?:--ext-diff|--textconv|--show-signature)(?:\s|$)",
        action,
    ):
        return _result(
            "git",
            "MODERATE",
            "REVIEW_FIRST",
            f"This Git {operation} asks Git to invoke an external diff, conversion, or signature-verification program.",
            ["Configured external programs may run while Git prepares the displayed result."],
            "Any side effects depend on the external program and are not established by the visible Git action.",
            [f"Run plain `git {operation}` without external-program options first, or inspect the configured program separately."],
            ["The visible action does not show which external program Git will invoke."],
            [f"git_{operation}", "git_external_command", "external_program_unknown"],
        )
    protected = bool(re.search(r"\b(?:main|master)\b", lowered))
    remote_delete = operation == "push" and bool(re.search(r"(?:--delete|:\S+)", lowered))

    if operation in ("status", "diff", "log", "show"):
        if not _git_read_options_are_safe(action, operation):
            return _result(
                "git",
                "MODERATE",
                "REVIEW_FIRST",
                f"This Git {operation} uses an option outside the v0.1 read-only allowlist.",
                ["The extra option may write output, invoke configured helpers, or otherwise change the behavior of the normally read-only operation."],
                "Any side effects cannot be determined safely from the supported option set.",
                [f"Run plain `git {operation}` first, then review the unsupported option separately."],
                ["The analyzer does not classify this option as proven read-only."],
                [f"git_{operation}", "unsupported_read_option"],
            )
        return _result(
            "git",
            "LOW",
            "SAFE_TO_APPROVE",
            f"This reads Git {operation} information without changing repository state.",
            ["Repository information may be displayed, but files and history are not changed."],
            "No change needs to be undone.",
            ["No safer alternative is needed for this read-only Git operation."],
            [],
            [f"git_{operation}", "read_only"],
        )
    if operation == "fetch":
        prune = bool(re.search(r"\bfetch\b[^;&|]*(?:--prune|\s-p\b)", lowered))
        dry_run = "--dry-run" in lowered
        fetch_tail = lowered.split("fetch", 1)[1]
        force_update = bool(
            re.search(r"(?:^|\s)(?:--force|-f|--update-head-ok|--refmap(?:=|\s))", fetch_tail)
        )
        refspec_update = any(
            re.match(r"^\+?[^:]+:.+", token)
            and "://" not in token
            and not re.match(r"^[^/]+@[^:]+:", token)
            for token in _tokens(action)
        )
        refspec_delete = next(
            (
                token
                for token in _tokens(action)
                if re.match(r"^:(?:refs/)?[A-Za-z0-9_.\-/]+$", token)
            ),
            None,
        )
        if refspec_delete and not dry_run:
            return _result(
                "git",
                "MODERATE",
                "REVIEW_FIRST",
                f"This fetch uses the empty-source refspec `{refspec_delete}` to delete a local Git reference.",
                ["The named local branch or tracking reference may disappear and its commits may become harder to find."],
                "Recovery requires the deleted reference's prior commit ID or an available reflog entry.",
                ["Record the current reference and delete it separately only after confirming it is stale and unneeded."],
                [],
                ["git_fetch", "fetch_ref_delete", "local_history_change"],
            )
        if (force_update or refspec_update) and not dry_run:
            return _result(
                "git",
                "HIGH" if "--update-head-ok" in lowered or "refs/heads/" in lowered else "MODERATE",
                "REVIEW_FIRST",
                "This fetch uses a forced or explicit ref mapping that can replace local Git references, not just download remote metadata.",
                ["A local branch or tracking reference may move to a different commit and make prior work harder to find."],
                "Recovery may require the previous commit ID or Git reflog; unrecorded reference positions are difficult to reconstruct.",
                ["Fetch without a destination refspec or force option first, inspect FETCH_HEAD, and update a local branch separately."],
                [],
                ["git_fetch", "forced_fetch_update", "local_history_change"],
            )
        if prune and not dry_run:
            return _result(
                "git",
                "MODERATE",
                "REVIEW_FIRST",
                "This fetches remote history and removes local remote-tracking references that no longer exist on the remote.",
                ["Names for stale remote branches may disappear from local Git metadata."],
                "A removed tracking reference can be recreated only if its commit is still known or available from a remote or reflog.",
                ["Run `git fetch --dry-run --prune` first and review which references would be removed."],
                [],
                ["git_fetch", "fetch_prune", "local_history_change"],
            )
        if prune and dry_run:
            return _result(
                "git",
                "LOW",
                "SAFE_TO_APPROVE",
                "This previews which stale remote-tracking references a pruned fetch would remove without changing them.",
                ["The planned reference updates and removals may be displayed; dry-run mode does not apply them."],
                "No change needs to be undone.",
                ["Review the preview before running the same fetch without `--dry-run`."],
                [],
                ["git_fetch", "fetch_prune", "dry_run", "read_only"],
            )
        if not _git_fetch_options_are_safe(action):
            return _result(
                "git",
                "MODERATE",
                "REVIEW_FIRST",
                "This Git fetch uses an option outside the v0.1 read-only allowlist.",
                ["The option may update local references, invoke a helper, or obtain hidden refspecs rather than performing a plain fetch."],
                "The analyzer cannot prove the option has no persistent side effect.",
                ["Run plain `git fetch` or a dry-run form first, and review the unsupported option separately."],
                ["The analyzer does not classify this fetch option as proven read-only."],
                ["git_fetch", "unsupported_read_option"],
            )
        return _result(
            "git",
            "LOW",
            "SAFE_TO_APPROVE",
            "This downloads remote Git history and updates remote-tracking references.",
            ["Local remote-tracking metadata changes; working files are not merged or overwritten."],
            "The fetched metadata can be refreshed again and does not replace local work.",
            ["No safer alternative is normally needed; inspect the fetched diff afterward."],
            [],
            ["git_fetch", "remote_read"],
        )
    if operation == "push":
        force = "--force" in lowered or " -f" in lowered
        force_lease = "--force-with-lease" in lowered
        signals = ["git_push", "remote_state"]
        if force:
            signals.append("force_with_lease" if force_lease else "force_push")
        if protected:
            signals.append("protected_branch")
        if remote_delete:
            signals.append("remote_delete")
        remote, branch = _git_push_destination(action)
        if force or remote_delete:
            summary = (
                f"This deletes branch or tag `{branch}` from remote repository `{remote}`."
                if remote_delete
                else (
                    f"This uses force-with-lease to replace remote branch `{branch}` on `{remote}` with local history. "
                    "The lease refuses the push if that remote branch changed since the last known remote state."
                    if force_lease
                    else f"This forcibly replaces remote branch `{branch}` on `{remote}` with local history."
                )
            )
            return _result(
                "git",
                "HIGH",
                "REVIEW_FIRST",
                summary,
                [f"Commits currently visible on shared remote `{remote}` branch or tag `{branch}` may disappear if they are absent locally."],
                "Recovery may be possible from old commit IDs, but it is not a simple undo and may require coordination.",
                ["Fetch first, compare local and remote histories, and use a normal push or a new branch when possible."],
                [],
                signals,
            )
        return _result(
            "git",
            "HIGH",
            "REVIEW_FIRST",
            f"This publishes local commits to shared branch `{branch}` on remote repository `{remote}`.",
            [f"Other people may base work on the new `{branch}` state, and automated checks or deployments may act on unintended commits once they are shared."],
            "A follow-up revert may undo code changes, but published history remains shared.",
            [f"Review the commits that exist locally but not on `{remote}/{branch}`, then use this normal non-forced push only if they are intended for that branch."],
            [],
            signals,
        )
    if operation == "reset" and "--hard" in lowered:
        return _result(
            "git",
            "HIGH",
            "REVIEW_FIRST",
            "This moves the current branch and discards tracked working-tree changes.",
            ["Uncommitted tracked changes can be lost, and recent commits may no longer be visible on the branch."],
            "Committed history may be recoverable through the reflog; uncommitted changes may not be recoverable.",
            ["Save a diff or create a temporary branch before resetting."],
            [],
            ["git_reset", "hard_reset", "destructive_local"],
        )
    if operation == "clean":
        dry_run = bool(re.search(r"(?:--dry-run|\s-n\b)", lowered))
        if dry_run:
            return _result(
                "git",
                "LOW",
                "SAFE_TO_APPROVE",
                "This previews untracked files that Git clean would remove.",
                ["No files are removed in dry-run mode."],
                "No change needs to be undone.",
                ["Review the preview before running Git clean without dry-run mode."],
                [],
                ["git_clean", "dry_run", "read_only"],
            )
        return _result(
            "git",
            "HIGH",
            "REVIEW_FIRST",
            "This permanently removes untracked files from the working tree.",
            ["Files Git does not track may be deleted, including generated work or local-only files."],
            "Git cannot restore untracked files; recovery depends on an external backup.",
            ["Run `git clean -nd` first and remove only confirmed disposable paths."],
            [],
            ["git_clean", "destructive_local"],
        )
    if operation == "pull":
        fast_forward_only = "--ff-only" in lowered
        return _result(
            "git",
            "MODERATE",
            "REVIEW_FIRST",
            (
                "This downloads remote changes and updates the current branch only when Git can move it straight forward without creating a merge commit."
                if fast_forward_only
                else "This downloads remote changes and integrates them into the current branch."
            ),
            [
                "Local files and the current branch may move to newer remote commits; if a straight-forward update is impossible, this command stops without integrating."
                if fast_forward_only
                else "Local files and branch history may change, and conflicts may require manual decisions."
            ],
            (
                "After a successful straight-forward update, returning to the old commit requires its commit ID or the Git reflog (Git's local record of recent branch positions)."
                if fast_forward_only
                else "An in-progress merge or rebase can often be aborted; afterward, recovery requires Git's saved branch-position history."
            ),
            ["Fetch first and inspect the incoming changes before integrating them."],
            [],
            ["git_pull", "local_history_change"],
        )
    if operation in ("rebase", "checkout", "restore", "reset"):
        risk = "HIGH" if re.search(r"(?:restore\s+\.|checkout\s+--\s+\.|reset\s+--merge)", lowered) else "MODERATE"
        return _result(
            "git",
            risk,
            "REVIEW_FIRST",
            f"This {operation} operation changes local Git history or working files.",
            ["The current branch, commit order, index, or tracked files may change."],
            "Recovery may be possible with the reflog or saved changes, but uncommitted work can be difficult to restore.",
            ["Inspect `git status` and save uncommitted changes before continuing."],
            [],
            [f"git_{operation}", "local_state_change"],
        )
    if operation == "branch" and re.search(r"(?:\s-[dD]\b|--delete|--force)", action):
        return _result(
            "git",
            "MODERATE",
            "REVIEW_FIRST",
            "This deletes a local Git branch reference.",
            ["The branch name disappears locally; unmerged commits may become harder to find."],
            "Commits are often recoverable through the reflog until Git prunes them.",
            ["Check whether the branch is merged and record its commit ID first."],
            [],
            ["git_branch_delete", "local_state_change"],
        )
    if operation == "tag" and re.search(r"(?:\s-d\b|--delete)", lowered):
        return _result(
            "git",
            "MODERATE",
            "REVIEW_FIRST",
            "This deletes a local Git tag reference.",
            ["The local tag name is removed, though the referenced commit normally remains."],
            "The tag can be recreated if its name and target commit are known.",
            ["Record the tag target before deleting it."],
            [],
            ["git_tag_delete", "local_state_change"],
        )
    if operation in ("add", "commit", "clone", "branch", "tag", "git"):
        return _result(
            "git",
            "MODERATE",
            "REVIEW_FIRST",
            f"This performs the local Git operation `{operation}`.",
            ["Local repository metadata, staged content, history, or files may change."],
            "Most local Git metadata changes can be adjusted with another Git operation, though committed content remains in history.",
            ["Inspect `git status` and the relevant diff before continuing."],
            [],
            [f"git_{operation}", "local_state_change"],
        )
    return None


def _analyze_packages(action: str) -> dict[str, Any] | None:
    lowered = action.lower()
    tokens = _tokens(action)
    manager = _command_name(tokens)
    if manager not in {"npm", "pnpm", "yarn", "pip", "pip3", "pipx", "brew", "apt", "apt-get"}:
        return None
    try:
        manager_index = next(i for i, token in enumerate(tokens) if token.lower() == manager)
    except StopIteration:
        manager_index = 0
    following_tokens = tokens[manager_index + 1 :]
    subcommand = (
        following_tokens[0].lower()
        if following_tokens and not following_tokens[0].startswith("-")
        else ""
    )
    read_subcommands = {"list", "ls", "show", "info", "view", "outdated", "audit", "freeze", "check"}
    script_subcommands = {
        "run", "run-script", "exec", "dlx", "npx", "node", "test", "start", "stop",
        "restart", "publish", "pack", "explore",
    }
    mutating_words = bool(re.search(r"\b(?:fix|install|uninstall|remove|purge|upgrade|update)\b", lowered))
    script = subcommand in script_subcommands
    read_only = subcommand in read_subcommands and not mutating_words and not script
    if read_only:
        return _result(
            "packages",
            "LOW",
            "SAFE_TO_APPROVE",
            f"This reads {manager} package information without installing or removing anything.",
            ["Package metadata may be downloaded or displayed; installed packages are not intentionally changed."],
            "No package change needs to be undone.",
            ["No safer alternative is normally needed for this read-only package query."],
            [],
            ["package_read", f"manager_{manager}"],
        )
    global_change = bool(
        re.search(r"(?:\s-g\b|--global\b|\bsudo\b)", lowered)
        or manager in ("pipx", "apt", "apt-get")
    )
    uninstall = bool(re.search(r"\b(?:uninstall|remove|purge)\b", lowered))
    upgrade = bool(re.search(r"\b(?:upgrade|update)\b", lowered))
    script = script or bool(re.search(r"\b(?:run-script|npx)\b", lowered))
    operation = "removes" if uninstall else "upgrades" if upgrade else "runs a package script for" if script else "installs"
    risk = "HIGH" if global_change else "MODERATE"
    package_candidates = [
        token
        for token in tokens[1:]
        if not token.startswith("-")
        and token.lower()
        not in {
            "install", "add", "remove", "uninstall", "purge", "upgrade", "update",
            "run", "exec", "dlx", "npx", "--", "sudo",
        }
    ]
    package_target = package_candidates[-1] if package_candidates else "the requested package"
    if manager in {"apt", "apt-get"}:
        operation_word = "remove" if uninstall else "upgrade" if upgrade else "install"
        return _result(
            "packages",
            "HIGH",
            "REVIEW_FIRST",
            f"This asks {manager} to {operation_word} the system package `{package_target}` for the whole operating system.",
            [f"System software and packages that `{package_target}` depends on may be installed, removed, or replaced."],
            f"A later `{manager} remove {package_target}` may remove the package, but changed dependencies, configuration files, and downloaded data may remain.",
            [f"Use `{manager} --simulate {operation_word} {package_target}` first to preview every package change, then confirm the package source and version."],
            ["The command does not show which package repository or exact version will be selected."],
            [
                "package_uninstall" if uninstall else "package_upgrade" if upgrade else "package_install",
                f"manager_{manager}",
                "global_install",
            ],
        )
    if manager in {"npm", "pnpm", "yarn"} and global_change:
        return _result(
            "packages",
            "HIGH",
            "REVIEW_FIRST",
            f"This installs `{package_target}` globally, making its commands available outside the current project.",
            ["Executable package code may run during installation, and the user-wide or system-wide JavaScript tool environment may change."],
            f"The package can usually be removed with `{manager} uninstall -g {package_target}`, but installation scripts may have changed other files.",
            [f"Prefer installing an exact reviewed version of `{package_target}` only inside this project, where the change is recorded in the project's dependency files."],
            ["The command does not pin an exact version or show what the package's installation scripts do."],
            ["package_install", f"manager_{manager}", "global_install"],
        )
    return _result(
        "packages",
        risk,
        "REVIEW_FIRST",
        f"This {operation} `{package_target}` using {manager}.",
        [
            "Installed code, dependency files, or executable commands may change."
            if not global_change
            else "The user or system-wide software environment may change outside this project."
        ],
        "The change can often be reversed by restoring dependency files or uninstalling/reinstalling packages, but scripts may have additional side effects.",
        ["Pin the exact package version, preview the dependency-file changes, and review any scripts the package runs during installation."],
        ["The command alone does not establish what every package-provided installation script will do."],
        [
            "package_uninstall" if uninstall else "package_upgrade" if upgrade else "package_script" if script else "package_install",
            f"manager_{manager}",
            "global_install" if global_change else "project_dependency_change",
        ],
    )


def _rm_targets(tokens: list[str]) -> list[str]:
    try:
        index = next(i for i, token in enumerate(tokens) if token.lower() in ("rm", "unlink"))
    except StopIteration:
        return []
    return [token for token in tokens[index + 1 :] if not token.startswith("-")]


def _output_redirection(action: str) -> tuple[int, str, str] | None:
    quote: str | None = None
    escaped = False
    substitution_depth = 0
    index = 0
    while index < len(action):
        char = action[index]
        following = action[index + 1] if index + 1 < len(action) else ""
        if escaped:
            escaped = False
            index += 1
            continue
        if char == "\\" and quote != "'":
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            index += 1
            continue
        if char in ("'", '"', "`"):
            quote = char
            index += 1
            continue
        if char in {"$", "<", ">", "="} and following == "(":
            substitution_depth += 1
            index += 2
            continue
        if char == ")" and substitution_depth:
            substitution_depth -= 1
            index += 1
            continue
        if char == ">" and substitution_depth == 0 and following != "(":
            operator = ">>" if following == ">" else ">"
            target_start = index + len(operator)
            while target_start < len(action) and action[target_start].isspace():
                target_start += 1
            descriptor_match = re.match(r"&(?:\d+|-)(?=$|[\s;&|])", action[target_start:])
            if descriptor_match:
                index = target_start + len(descriptor_match.group(0))
                continue
            if target_start < len(action) and action[target_start] == "&":
                target_start += 1
                while target_start < len(action) and action[target_start].isspace():
                    target_start += 1
            target_match = re.match(r"[^\s;&|]+", action[target_start:])
            target = target_match.group(0) if target_match else ""
            return index, operator, target.strip("'\"") or "the destination file"
        index += 1
    return None


def _redirection_details(action: str) -> tuple[str, str, bool]:
    redirection = _output_redirection(action)
    if redirection is None:
        return "the destination file", "new content", False
    position, operator, target = redirection
    prefix = action[:position].strip()
    content = "new content"
    echo_match = re.match(r"(?:echo|printf)\s+(.+)$", prefix, re.IGNORECASE)
    if echo_match:
        content = echo_match.group(1).strip().strip("'\"") or "an empty value"
    return target, content, operator == ">>"


def _redirection_result(action: str) -> dict[str, Any] | None:
    if _output_redirection(action) is None:
        return None
    target, content, append = _redirection_details(action)
    summary = (
        f"This appends `{content}` to `{target}`."
        if append
        else f"This replaces the contents of `{target}` with `{content}`; if the file does not exist, it creates it."
    )
    impact = [
        f"Existing contents in `{target}` will remain and new output will be added at the end."
        if append
        else f"Any existing contents in `{target}` will be discarded before new output is written."
    ]
    return _result(
        "filesystem",
        "MODERATE",
        "REVIEW_FIRST",
        summary,
        impact,
        f"Restoring the previous contents of `{target}` requires version control, an editor history, or a backup; this action does not create one.",
        [f"Write to a temporary file, compare it with `{target}`, and preserve a backup before replacing the original."],
        [f"The action does not show whether `{target}` already exists or contains unique data."],
        ["filesystem_write", "possible_overwrite" if not append else "file_append"],
    )


def _wrapper_output_result(action: str) -> dict[str, Any] | None:
    tokens = _tokens(action)
    index = 0
    while index < len(tokens) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", tokens[index]):
        index += 1
    if index >= len(tokens):
        return None
    wrapper = tokens[index].replace("\\", "/").rsplit("/", 1)[-1].lower()
    if wrapper == "nohup":
        if _output_redirection(action) is not None:
            return None
        return _result(
            "filesystem",
            "MODERATE",
            "REVIEW_FIRST",
            "This runs a command with nohup and may create or append its output to `nohup.out`.",
            ["`nohup.out` may be created or changed in the current directory or user home directory."],
            "Restoring previous `nohup.out` contents requires a backup or version history.",
            ["Redirect output to a new, explicit, confirmed path or run the command without nohup when persistence is unnecessary."],
            ["The action does not show whether `nohup.out` already contains unique data or which fallback directory nohup will use."],
            ["wrapper_output", "filesystem_write", "file_append"],
        )
    if wrapper != "time":
        return None
    target = None
    append = "-a" in tokens or "--append" in tokens
    for option_index, token in enumerate(tokens[index + 1 :], start=index + 1):
        if token in {"-o", "--output"} and option_index + 1 < len(tokens):
            target = tokens[option_index + 1]
            break
        if token.startswith("--output="):
            target = token.split("=", 1)[1]
            break
    if not target:
        return None
    return _result(
        "filesystem",
        "MODERATE",
        "REVIEW_FIRST",
        f"This writes command timing information to `{target}`{' by appending' if append else ' and may replace existing contents'}.",
        [f"`{target}` may be created or changed."],
        "Restoring previous timing-file contents requires a backup or version history.",
        ["Display timing information normally first, or use a new confirmed output path."],
        [f"The action does not show whether `{target}` already contains unique data."],
        ["wrapper_output", "filesystem_write", "file_append" if append else "possible_overwrite"],
    )


def _find_embedded_action(tokens: list[str]) -> str:
    for index, token in enumerate(tokens):
        if token.lower() not in {"-exec", "-execdir", "-ok", "-okdir"}:
            continue
        embedded: list[str] = []
        for item in tokens[index + 1 :]:
            if item in {";", "+", "\\;"}:
                break
            embedded.append(item)
        return " ".join(embedded).strip()
    return ""


def _analyze_filesystem(action: str) -> dict[str, Any] | None:
    lowered = action.lower().strip()
    tokens = _tokens(action)
    command = _command_name(tokens)
    redirected_result = _redirection_result(action)
    if command in {"tree", "less"}:
        output_options = {"-o", "--output"} if command == "tree" else {"-o", "-O", "--log-file", "--LOG-FILE"}
        output_target = None
        for index, token in enumerate(tokens):
            if token in output_options and index + 1 < len(tokens):
                output_target = tokens[index + 1]
                break
            if token.startswith("--output=") or token.startswith("--log-file="):
                output_target = token.split("=", 1)[1]
                break
        if output_target:
            return _result(
                "filesystem",
                "MODERATE",
                "REVIEW_FIRST",
                f"This writes {command} output to `{output_target}`.",
                [f"`{output_target}` may be created or its existing contents may be replaced."],
                "Restoring overwritten contents requires version control, editor history, or a backup.",
                [f"Display the output first, then write it to a new confirmed path instead of `{output_target}`."],
                [f"The action does not show whether `{output_target}` already contains unique data."],
                ["filesystem_write", "possible_overwrite"],
            )
    if command == "find":
        try:
            command_index = next(i for i, token in enumerate(tokens) if token.lower() == "find")
        except StopIteration:
            command_index = 0
        paths: list[str] = []
        for token in tokens[command_index + 1 :]:
            if token.startswith("-") or token in {"!", "(", ")"}:
                break
            paths.append(token)
        paths = paths or ["."]
        normalized = {path.rstrip("/") or "/" for path in paths}
        catastrophic = bool(normalized & {"/", "/*", "~", "$HOME", "${HOME}", "/Users", "/home", "/System"})
        repository_wide = bool(normalized & {".", "./", "*"})
        delete_action = "-delete" in lowered
        exec_action = bool(re.search(r"(?:^|\s)-(?:exec|execdir|ok|okdir)(?:\s|$)", lowered))
        file_output_action = bool(re.search(r"(?:^|\s)-(?:fprint|fprint0|fprintf|fls)(?:\s|$)", lowered))
        embedded_delete = exec_action and bool(
            re.search(r"-(?:exec|execdir|ok|okdir)\s+(?:[^;]+\s)?(?:rm|unlink)\b", lowered)
        )
        embedded_action = _find_embedded_action(tokens) if exec_action else ""
        embedded_filesystem = _analyze_filesystem(embedded_action) if embedded_action else None
        if embedded_filesystem is not None and embedded_filesystem["risk"] == "CRITICAL":
            find_context = _result(
                "filesystem",
                "HIGH",
                "REVIEW_FIRST",
                f"This uses `find` to run `{embedded_action}` on paths matched under {', '.join(f'`{path}`' for path in paths)}.",
                ["The embedded command may run once for every matched path."],
                "Recovery depends on the embedded command and the number of affected matches.",
                ["Print and inspect all matches without an execution action first."],
                ["The number and identity of matched paths are not shown."],
                ["find_exec", "broad_scope"],
            )
            return _combine_analyses(
                [find_context, embedded_filesystem],
                ["find matching paths", embedded_action],
                "This find action",
            )
        if delete_action or exec_action or file_output_action:
            risk = "CRITICAL" if catastrophic else "HIGH"
            recommendation = (
                "DO_NOT_APPROVE"
                if catastrophic or (repository_wide and (delete_action or embedded_delete)) or embedded_delete
                else "REVIEW_FIRST"
            )
            operation = (
                "delete every matching path"
                if delete_action
                else "run a deletion command on every matching path"
                if embedded_delete
                else "write matching results to a local file"
                if file_output_action
                else "run another command on every matching path"
            )
            scope = ", ".join(f"`{path}`" for path in paths)
            return _result(
                "filesystem",
                risk,
                recommendation,
                f"This uses `find` to {operation} under {scope}.",
                ["Every matching file or directory in that search scope may be changed or permanently removed."],
                "`find` has no built-in undo; recovery depends on version control or an external backup.",
                ["Run the same `find` expression without `-delete` or `-exec` first, inspect every match, and then act only on explicit confirmed paths."],
                ["The visible action does not establish whether every matched path is disposable or backed up."],
                [
                    "find_delete" if delete_action else "find_output" if file_output_action else "find_exec",
                    "filesystem_delete" if delete_action or embedded_delete else "filesystem_write",
                    "recursive_delete" if delete_action or embedded_delete else "broad_scope",
                ]
                + (["catastrophic_scope"] if catastrophic else [])
                + (["repository_wide_delete"] if repository_wide and (delete_action or embedded_delete) else []),
            )
        if redirected_result is not None:
            return redirected_result
        return _result(
            "filesystem",
            "LOW",
            "SAFE_TO_APPROVE",
            f"This searches for local paths under {', '.join(f'`{path}`' for path in paths)} without intentionally changing them.",
            ["Matching file names and metadata may be displayed."],
            "No filesystem change needs to be undone.",
            ["Limit the search path if the results may reveal sensitive filenames."],
            [],
            ["filesystem_read", "find_read", "read_only"],
        )
    if command == "file" and any(token in {"-C", "--compile"} for token in tokens[1:]):
        magic_target = next(
            (tokens[i + 1] for i, token in enumerate(tokens[:-1]) if token in {"-m", "--magic-file"}),
            "the selected magic definition",
        )
        return _result(
            "filesystem",
            "MODERATE",
            "REVIEW_FIRST",
            f"This compiles `{magic_target}` into a local magic database file.",
            ["A compiled `.mgc` file may be created or replaced."],
            "Recovery requires removing the generated file or restoring its previous version.",
            ["Validate the magic definition without `--compile`, then compile it only to a new confirmed destination."],
            ["The exact generated filename and whether it already exists are not shown."],
            ["file_compile", "filesystem_write", "possible_overwrite"],
        )
    if command == "less":
        initial_shell = next((token[2:] for token in tokens[1:] if token.startswith(("+!", "+|"))), "")
        less_environment = next(
            (
                token.split("=", 1)[1].lstrip("|")
                for token in tokens
                if token.startswith(("LESSOPEN=|", "LESSCLOSE="))
            ),
            "",
        )
        embedded = initial_shell or less_environment
        if embedded:
            context = _result(
                "filesystem",
                "HIGH",
                "REVIEW_FIRST",
                "This less invocation supplies a command that the viewer may execute through a shell.",
                ["The embedded command can change files or services available to the current user."],
                "Recovery depends entirely on the embedded command.",
                ["Remove the shell command and open the file with a plain read-only viewer invocation."],
                [],
                ["less_shell", "embedded_code", "arbitrary_execution"],
            )
            return _combine_analyses(
                [context, analyze_action(embedded.replace("%s", "").strip())],
                ["open viewer", embedded],
                "This less shell action",
            )
    read_commands = {"ls", "pwd", "stat", "file", "head", "tail", "wc", "du", "tree"}
    if command in read_commands:
        if redirected_result is not None:
            return redirected_result
        return _result(
            "filesystem",
            "LOW",
            "SAFE_TO_APPROVE",
            "This reads local filesystem information without intentionally changing files.",
            ["File names, metadata, or contents may be displayed."],
            "No filesystem change needs to be undone.",
            ["Limit the path if the output may reveal sensitive filenames or content."],
            [],
            ["filesystem_read", "read_only"],
        )
    if command in {"rm", "unlink"}:
        targets = _rm_targets(tokens)
        recursive = bool(re.search(r"(?:\s-[a-z]*r|--recursive)", lowered))
        force = bool(re.search(r"(?:\s-[a-z]*f|--force)", lowered))
        normalized = {target.rstrip("/") or "/" for target in targets}
        catastrophic = bool(
            normalized & {"/", "/*", "~", "$HOME", "${HOME}", "/Users", "/home", "/System"}
            or "--no-preserve-root" in lowered
        )
        repository_wide = bool(normalized & {".", "./", "*"})
        regenerable = bool(
            normalized
            and all(
                target.lower().rstrip("/")
                in {"node_modules", "./node_modules", ".cache", "./.cache", "dist", "./dist", "build", "./build"}
                for target in normalized
            )
        )
        if catastrophic:
            return _result(
                "filesystem",
                "CRITICAL",
                "DO_NOT_APPROVE",
                "This can recursively delete a system, home, or filesystem-root scope.",
                ["A very large portion of the computer's files, applications, or user data could be permanently removed."],
                "There is no normal undo; recovery would depend on backups and may require rebuilding the system.",
                ["Do not run it. Replace the target with one explicit, verified disposable directory."],
                [],
                ["filesystem_delete", "recursive_delete", "catastrophic_scope"],
            )
        if repository_wide:
            return _result(
                "filesystem",
                "HIGH",
                "DO_NOT_APPROVE",
                "This can recursively delete the current directory or all of its visible contents.",
                ["Project files, uncommitted work, and local-only data may be permanently removed."],
                "Version-controlled files may be recoverable, but untracked or uncommitted files may not be.",
                ["List the directory first and delete only explicit disposable paths."],
                [],
                ["filesystem_delete", "recursive_delete", "repository_wide_delete"],
            )
        if regenerable:
            return _result(
                "filesystem",
                "MODERATE",
                "REVIEW_FIRST",
                "This deletes a generated dependency, cache, or build directory.",
                ["Generated local files are removed and may take time or network access to recreate."],
                "The directory can normally be recreated from project definitions, but local modifications inside it would be lost.",
                ["Confirm the exact path and verify it contains only generated files."],
                [],
                ["filesystem_delete", "recursive_delete" if recursive else "file_delete", "regenerable_target"],
            )
        risk = "HIGH" if recursive else "MODERATE"
        return _result(
            "filesystem",
            risk,
            "REVIEW_FIRST",
            "This deletes local files or directories.",
            ["The specified paths may be permanently removed."],
            "Recovery depends on version control, trash behavior, or an external backup; forced deletion usually bypasses easy recovery.",
            ["List and verify each target, remove force/recursive flags when possible, and preserve a backup."],
            ["The action does not show whether the target contains unique or backed-up data."],
            ["filesystem_delete", "recursive_delete" if recursive else "file_delete"]
            + (["forced_delete"] if force else []),
        )
    if command in {"chmod", "chown"}:
        broad = " -r" in lowered or bool(re.search(r"\s/(?:\s|$)", lowered))
        positional = [token for token in tokens[1:] if not token.startswith("-")]
        if command == "chmod":
            mode = positional[0] if positional else "the requested mode"
            target = positional[1] if len(positional) > 1 else "the requested path"
            if mode == "777":
                summary = f"This recursively grants every user read, write, and execute permission on `{target}`." if broad else f"This grants every user read, write, and execute permission on `{target}`."
                impact = [f"Any local account or process able to reach `{target}` may read, alter, or run its contents; recursive mode applies this to everything underneath it."]
                safer = [f"Record current modes, then grant only the specific user and permission needed on an explicit subpath instead of applying `777` to `{target}`."]
            else:
                summary = f"This changes permissions on `{target}` to `{mode}`{' recursively' if broad else ''}."
                impact = [f"Programs or users may gain or lose access to `{target}` and{' everything beneath it' if broad else ' its contents'}." ]
                safer = [f"Record the current mode of `{target}` and grant only the minimum permission required."]
        else:
            target = positional[-1] if positional else "the requested path"
            summary = f"This changes ownership of `{target}`{' and everything beneath it' if broad else ''}."
            impact = [f"Programs or users may gain or lose ownership-based access to `{target}`."]
            safer = [f"Record the current owner of `{target}` and limit the ownership change to one explicit path."]
        return _result(
            "filesystem",
            "HIGH" if broad else "MODERATE",
            "REVIEW_FIRST",
            summary,
            impact,
            (
                "The previous permission mode can be restored only if it was recorded or can be reconstructed."
                if command == "chmod"
                else "The previous owner can be restored only if it was recorded or can be reconstructed."
            ),
            safer,
            [],
            ["permission_change", "broad_scope" if broad else "limited_scope"],
        )
    if redirected_result is not None:
        return redirected_result
    if command in {"mv", "cp", "mkdir", "touch"}:
        overwrite = bool(re.search(r"\b(?:cp|mv)\s+-f\b", lowered))
        return _result(
            "filesystem",
            "MODERATE",
            "REVIEW_FIRST",
            "This creates, copies, or moves local files.",
            ["Local paths or file contents may change, and an existing destination may be overwritten."],
            "It is usually reversible if the previous destination still exists or is backed up.",
            ["Inspect the source and destination and avoid overwrite flags until the target is confirmed."],
            ["The action does not establish whether the destination already exists or contains unique data."],
            ["filesystem_write", "possible_overwrite" if overwrite else "file_creation"],
        )
    if command == "cat":
        return _result(
            "filesystem",
            "LOW",
            "SAFE_TO_APPROVE",
            "This reads a local file without intentionally changing it.",
            ["The file contents may be displayed."],
            "No filesystem change needs to be undone.",
            ["Confirm the file is not sensitive before displaying it."],
            [],
            ["filesystem_read", "read_only"],
        )
    if command in {"less", "more"}:
        return _result(
            "filesystem",
            "MODERATE",
            "REVIEW_FIRST",
            f"This opens a file in the interactive `{command}` viewer.",
            ["File content is displayed; interactive viewer configuration or commands may invoke additional behavior."],
            "The visible read itself needs no undo, but hidden viewer commands cannot be verified from this action.",
            ["Use `cat`, `head`, or another non-interactive read command for a limited non-sensitive file."],
            ["The analyzer cannot establish the viewer's runtime configuration."],
            ["filesystem_read", "interactive_viewer"],
        )
    return None


def _analyze_unknown(action: str) -> dict[str, Any]:
    lowered = action.lower().strip()
    tokens = _tokens(action)
    command = _command_name(tokens)
    if not lowered:
        return _result(
            "unknown",
            "MODERATE",
            "REVIEW_FIRST",
            "No actionable command or operation was provided.",
            ["No specific change can be determined from empty input."],
            "There is no identified action to undo.",
            ["Ask the agent to show the complete action before approving anything."],
            ["The candidate input is empty or malformed."],
            ["unsupported_input"],
        )
    if re.search(r"\b(?:python\d*\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|bash\s+-c|sh\s+-c)\b", lowered):
        interpreter_match = re.search(r"\b(python\d*|node|ruby|perl|bash|sh)\s+(?:-c|-e)\b", lowered)
        interpreter = interpreter_match.group(1) if interpreter_match else "an interpreter"
        return _result(
            "unknown",
            "HIGH",
            "REVIEW_FIRST",
            f"This asks `{interpreter}` to execute the quoted text as code. The visible text may be invalid code or instruction-like prose, but approving it still invokes a general-purpose interpreter.",
            [f"Valid embedded `{interpreter}` code could read or change any files, data, or services available to the current user."],
            "Reversibility cannot be determined without understanding every operation in the embedded code.",
            ["Ask for the embedded code as a separate file and review it line by line before running it."],
            ["The analyzer cannot safely infer every side effect of arbitrary embedded code."],
            ["embedded_code", "arbitrary_execution"],
        )
    if command == "date" and (
        re.search(r"(?:^|\s)(?:-s|--set)(?:=|\s)", action)
        or any(token.startswith("-s") and token != "-s" for token in tokens[1:])
        or any(token == "-a" or token.startswith("--adjust=") for token in tokens[1:])
        or any(re.fullmatch(r"\d{8,14}(?:\.\d{2})?", token) for token in tokens[1:])
    ):
        return _result(
            "unknown",
            "HIGH",
            "REVIEW_FIRST",
            "This asks the operating system to change its clock rather than only display the current time.",
            ["Logs, certificates, builds, scheduled tasks, and network authentication may behave incorrectly after a clock change."],
            "The clock can be set again, but timestamp and automation effects that already occurred may not be reversible.",
            ["Display the current time first and use the system's approved time-synchronization service instead of setting it directly."],
            [],
            ["system_time_change", "system_state"],
        )
    if re.match(r"^(?:echo|printf|date|whoami|uname|which|command\s+-v)\b", lowered):
        return _result(
            "unknown",
            "LOW",
            "SAFE_TO_APPROVE",
            "This displays text or basic local information without an identified persistent change.",
            ["Information is printed to the current output."],
            "No persistent change needs to be undone.",
            ["No safer alternative is needed based on the visible action."],
            [],
            ["benign_output", "read_only"],
        )
    if re.search(r"\b(?:curl|wget)\b", lowered):
        return _result(
            "unknown",
            "MODERATE",
            "REVIEW_FIRST",
            "This communicates with a remote network location.",
            ["Data may be downloaded, uploaded, or displayed depending on the options."],
            "Network disclosure cannot be undone; downloaded files can usually be removed.",
            ["Verify the destination and review all transmitted data and output paths."],
            ["The destination's ownership and response content are not established by the command alone."],
            ["network_access"],
        )
    return _result(
        "unknown",
        "MODERATE",
        "REVIEW_FIRST",
        "The analyzer does not recognize this action well enough to describe it confidently.",
        ["The action may have side effects that are not visible to the supported v0.1 rules."],
        "Reversibility cannot be determined from the available information.",
        ["Ask the agent to break the action into a supported, explicit command and explain its target."],
        ["The action is unsupported or malformed, so important context may be missing."],
        ["unsupported_action"],
    )


def _analyze_single(action: str) -> dict[str, Any]:
    for analyzer in (
        _analyze_secrets,
        _analyze_database,
        _analyze_git,
        _analyze_packages,
        _analyze_filesystem,
    ):
        result = analyzer(action)
        if result is not None:
            return result
    return _analyze_unknown(action)


def analyze_action(action: str) -> dict[str, Any]:
    """Analyze untrusted candidate text as inert data and return structured JSON data."""
    candidate = action if isinstance(action, str) else str(action)
    direct_secret = _analyze_secrets(candidate)
    if direct_secret is not None and "credential_exfiltration" in direct_secret["signals"]:
        return direct_secret
    pipeline_transfer = _secret_pipeline_transfer(candidate)
    if pipeline_transfer is not None:
        return pipeline_transfer
    sub_actions = _execution_order(candidate)
    if not sub_actions:
        sub_actions = [candidate]
    analyses = [_analyze_single(item) for item in sub_actions]
    redirection = _redirection_result(candidate)
    if redirection is not None and not any(
        "filesystem_write" in analysis["signals"] for analysis in analyses
    ):
        analyses.append(redirection)
        sub_actions.append("output redirection")
    wrapper_output = _wrapper_output_result(candidate)
    if wrapper_output is not None:
        analyses.append(wrapper_output)
        sub_actions.append("wrapper output file")

    if len(analyses) == 1:
        return analyses[0]
    return _combine_analyses(analyses, sub_actions)


def format_explanation(analysis: dict[str, Any]) -> str:
    """Render the six required plain-language sections from structured data."""
    impact = "\n".join(f"- {item}" for item in analysis["impact"]) or "- No material change was identified."
    safer = (
        "\n".join(f"- {item}" for item in analysis["safer_alternatives"])
        or "- No safer alternative was identified from the available information."
    )
    uncertainty = ""
    if analysis["uncertainties"]:
        uncertainty = "\n\nKnown uncertainty:\n" + "\n".join(
            f"- {item}" for item in analysis["uncertainties"]
        )
    return (
        f"## Risk\n{RISK_LABELS[analysis['risk']]}\n\n"
        f"## What this does\n{analysis['action_summary']}\n\n"
        f"## What could change\n{impact}{uncertainty}\n\n"
        f"## Can it be undone?\n{analysis['reversibility']}\n\n"
        f"## Safer option\n{safer}\n\n"
        f"## Recommendation\n{analysis['recommendation']}"
    )


def _schema_is_valid(result: dict[str, Any]) -> bool:
    if any(field not in result for field in REQUIRED_FIELDS):
        return False
    if any(not isinstance(result[field], str) or not result[field] for field in ("domain", "risk", "recommendation", "action_summary", "reversibility")):
        return False
    if any(not isinstance(result[field], list) for field in ("impact", "safer_alternatives", "uncertainties", "signals")):
        return False
    return True


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    candidate = sys.stdin.read() if arguments == ["--stdin"] else " ".join(arguments)
    result = analyze_action(candidate)
    if not _schema_is_valid(result):
        result = _analyze_unknown("")
    print(json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
