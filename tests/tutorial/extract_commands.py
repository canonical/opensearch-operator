#!/usr/bin/env python3
# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Extract shell code blocks from MyST Markdown tutorial files.

Usage
-----
    # Auto-discover: process all .md files with spread metadata in a directory.
    python3 extract_commands.py docs/tutorial/ tests/tutorial/

    # Explicit pairs: one or more <input.md> <output.sh> pairs.
    python3 extract_commands.py docs/tutorial/environment.md \
        tests/tutorial/environment.sh

    # Print to stdout (no output file argument)
    python3 extract_commands.py docs/tutorial/environment.md

What gets extracted
-------------------
Only fenced code blocks whose opening fence is exactly:

    ```shell

Any other language tag (``bash``, ``text``, ``console``, etc.) is ignored.

Annotations
-----------
Annotations are HTML comments placed before or between fenced code blocks.
They control how blocks are extracted and what additional commands are emitted.
See README.md for full reference.
"""

import re
import shlex
import sys
from pathlib import Path

SKIP_MARKER = "<!-- test:skip -->"
_SLEEP_PATTERN = re.compile(r"<!--\s*test:wait\s+--seconds\s+(\d+)\s*-->")
_AWAIT_IDLE_PATTERN = re.compile(r"<!--\s*test:await-idle(.*?)-->")
_RETRY_PATTERN = re.compile(r"<!--\s*test:retry\s+(.*?)-->")
_RUN_WITH_TIMEOUT_PATTERN = re.compile(
    r"<!--\s*test:run-with-timeout\s+--seconds\s+(\d+)\s*-->"
)
_SET_VARIABLES_START = re.compile(r"<!--\s*test:set-variables\s*$")
_RUN_HIDDEN_START = re.compile(r"<!--\s*test:run\s*$")
_ASSERT_START = re.compile(r"<!--\s*test:assert\s*$")
_SPREAD_META_START = re.compile(r"<!--\s*test:spread\s*$")
_SHELL_OPEN = re.compile(r"^```shell\s*$")
_FENCE_CLOSE = re.compile(r"^```\s*$")


def _build_retry_command(args_str: str) -> str:
    """Build a ``retry_until_success`` call from ``helpers.sh``.

    Parses the inline arguments from a ``<!-- test:retry ... -->`` annotation
    and returns a shell command that calls ``retry_until_success``.
    """
    timeout = 1200
    interval = 120
    description = "command"
    command_parts: list[str] = []

    tokens = shlex.split(args_str) if args_str.strip() else []
    i = 0
    while i < len(tokens):
        if tokens[i] == "--timeout" and i + 1 < len(tokens):
            timeout = int(tokens[i + 1])
            i += 2
        elif tokens[i] == "--interval" and i + 1 < len(tokens):
            interval = int(tokens[i + 1])
            i += 2
        elif tokens[i] == "--description" and i + 1 < len(tokens):
            description = tokens[i + 1]
            i += 2
        elif tokens[i] == "--":
            command_parts = tokens[i + 1 :]
            break
        else:
            i += 1

    parts = [
        "retry_until_success",
        "--timeout",
        str(timeout),
        "--interval",
        str(interval),
        "--description",
        shlex.quote(description),
        "--",
    ]
    parts.extend(shlex.quote(p) for p in command_parts)
    return " ".join(parts)


def _build_await_idle_command(args_str: str) -> str:
    """Build a ``wait_idle`` call from ``helpers.sh``.

    The ``wait_idle`` function polls ``juju status`` until every unit is
    active/idle (with optional allow-blocked exceptions).
    """
    timeout = 1200
    allow_blocked: list[str] = []

    tokens = shlex.split(args_str) if args_str.strip() else []
    i = 0
    while i < len(tokens):
        if tokens[i] == "--timeout" and i + 1 < len(tokens):
            timeout = int(tokens[i + 1])
            i += 2
        elif tokens[i] == "--allow-blocked" and i + 1 < len(tokens):
            allow_blocked = [
                a.strip() for a in tokens[i + 1].split(",") if a.strip()
            ]
            i += 2
        else:
            i += 1

    parts = ["wait_idle", "--timeout", str(timeout)]
    if allow_blocked:
        parts.extend(["--allow-blocked", ",".join(allow_blocked)])

    return " ".join(parts)


def _parse_set_variables_block(
    lines: list[str], start: int
) -> tuple[str, list[tuple[str, str]], int]:
    """Parse a <!-- test:set-variables ... --> block starting at line `start`.

    Returns (bash_snippet, substitutions, next_index) where:
      - bash_snippet     is the generated variable-assignment bash code
      - substitutions    is [(placeholder, shell_var_ref), ...] for later replacement
      - next_index       is the index of the first line after the closing -->
    """
    i = start + 1
    command = ""
    mappings: list[tuple[str, str]] = []  # [(var_name, field_name), ...]

    while i < len(lines):
        raw = lines[i]
        if "-->" in raw:
            i += 1
            break
        stripped = raw.strip()
        if stripped and ":" in stripped:
            key, _, value = stripped.partition(":")
            key, value = key.strip(), value.strip()
            if key == "command":
                command = value
            elif key and value:
                mappings.append((key, value))
        i += 1

    if not command:
        return "", [], i

    snippet_lines = [f"_CMD_OUTPUT=$({command})"]
    substitutions: list[tuple[str, str]] = []
    for var_name, field_name in mappings:
        snippet_lines.append(
            f"{var_name}=$(echo \"$_CMD_OUTPUT\" | grep '{field_name}:'"
            f" | awk '{{print $2}}')"
        )
        substitutions.append((f"<{field_name}>", f"${{{var_name}}}"))

    return "\n".join(snippet_lines), substitutions, i


def _parse_run_hidden_block(
    lines: list[str], start: int, active_substitutions: list[tuple[str, str]]
) -> tuple[str, int]:
    """Parse a <!-- test:run ... --> block starting at line `start`.

    Returns (bash_snippet, next_index).
    """
    i = start + 1
    cmd_lines: list[str] = []

    while i < len(lines):
        raw = lines[i]
        if "-->" in raw:
            i += 1
            break
        stripped = raw.rstrip()
        if stripped:
            cmd_lines.append(stripped)
        i += 1

    content = "\n".join(cmd_lines)
    for placeholder, variable in active_substitutions:
        content = content.replace(placeholder, variable)
    return content, i


def _handle_marker_line(
    line: str,
    blocks: list[str],
) -> str | None:
    """Check *line* for a standalone annotation marker.

    Returns a short tag (``"skip"``, ``"sleep"``, ``"await_idle"``) when
    the line was consumed, or ``None`` when the line is not a marker.
    """
    stripped = line.strip()

    if stripped == SKIP_MARKER:
        return "skip"

    sleep_match = _SLEEP_PATTERN.match(stripped)
    if sleep_match:
        blocks.append(f"sleep {sleep_match.group(1)}")
        return "sleep"

    await_idle_match = _AWAIT_IDLE_PATTERN.match(stripped)
    if await_idle_match:
        args = await_idle_match.group(1).strip()
        blocks.append(_build_await_idle_command(args))
        return "await_idle"

    retry_match = _RETRY_PATTERN.match(stripped)
    if retry_match:
        args = retry_match.group(1).strip()
        blocks.append(_build_retry_command(args))
        return "retry"

    return None


def _collect_shell_block(
    lines: list[str],
    start: int,
    skip: bool,
    timeout_seconds: int | None,
    active_substitutions: list[tuple[str, str]],
    blocks: list[str],
) -> int:
    """Read a shell fence starting at *start* (one past the opening fence).

    Appends the processed content to *blocks* (unless *skip* is True) and
    returns the index of the first line after the closing fence.
    """
    i = start
    block_lines: list[str] = []
    while i < len(lines) and not _FENCE_CLOSE.match(lines[i]):
        block_lines.append(lines[i])
        i += 1
    i += 1  # consume closing fence

    if not skip and block_lines:
        content = "\n".join(block_lines)
        for placeholder, variable in active_substitutions:
            content = content.replace(placeholder, variable)
        if timeout_seconds is not None:
            blocks.append(
                f"( timeout {timeout_seconds} bash << 'TUTORIAL_TIMEOUT_EOF'\n"
                f"{content}\n"
                f"TUTORIAL_TIMEOUT_EOF\n) || true"
            )
        else:
            blocks.append(content)
    return i


class _ParseState:
    """Mutable state carried through the extraction loop."""

    __slots__ = ("skip_next", "run_with_timeout_seconds", "active_substitutions")

    def __init__(self) -> None:
        self.skip_next: bool = False
        self.run_with_timeout_seconds: int | None = None
        self.active_substitutions: list[tuple[str, str]] = []


def _handle_run_with_timeout(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    match = _RUN_WITH_TIMEOUT_PATTERN.match(lines[i].strip())
    state.run_with_timeout_seconds = int(match.group(1))  # type: ignore[union-attr]
    return i + 1


def _handle_set_variables(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    snippet, substitutions, next_i = _parse_set_variables_block(lines, i)
    if snippet:
        blocks.append(snippet)
    state.active_substitutions.extend(substitutions)
    return next_i


def _handle_spread_meta(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    j = i
    while j < len(lines) and "-->" not in lines[j]:
        j += 1
    return j + 1


def _handle_assert(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    snippet, next_i = _parse_run_hidden_block(lines, i, state.active_substitutions)
    if snippet:
        blocks.append(f"# --- Test assertion ---\n{snippet}")
    return next_i


def _handle_run_hidden(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    snippet, next_i = _parse_run_hidden_block(lines, i, state.active_substitutions)
    if snippet:
        blocks.append(snippet)
    return next_i


def _handle_shell_open(
    lines: list[str],
    i: int,
    blocks: list[str],
    state: _ParseState,
) -> int:
    next_i = _collect_shell_block(
        lines,
        i + 1,
        state.skip_next,
        state.run_with_timeout_seconds,
        state.active_substitutions,
        blocks,
    )
    state.skip_next = False
    state.run_with_timeout_seconds = None
    return next_i


# Each entry is (pattern, handler).  The pattern is tested against the
# stripped line for multi-line annotations, or the raw line for shell fences.
_BLOCK_HANDLERS: list[tuple[re.Pattern[str], bool, object]] = [
    (_RUN_WITH_TIMEOUT_PATTERN, True, _handle_run_with_timeout),
    (_SET_VARIABLES_START, True, _handle_set_variables),
    (_SPREAD_META_START, True, _handle_spread_meta),
    (_ASSERT_START, True, _handle_assert),
    (_RUN_HIDDEN_START, True, _handle_run_hidden),
    (_SHELL_OPEN, False, _handle_shell_open),
]


def extract_shell_blocks(source: str) -> list[str]:
    """Return shell code block contents and generated commands from Markdown.

    Each returned string is either the raw content between shell fences, a
    ``sleep N`` line, a ``wait_idle`` command, or injected code from
    other annotations.  Blocks marked with ``<!-- test:skip -->`` are omitted.
    """
    lines = source.splitlines()
    blocks: list[str] = []
    state = _ParseState()
    i = 0

    while i < len(lines):
        line = lines[i]

        # Detect standalone annotation markers (skip / sleep / await_idle).
        marker = _handle_marker_line(line, blocks)
        if marker == "skip":
            state.skip_next = True
            i += 1
            continue
        if marker is not None:
            i += 1
            continue

        # Try multi-line annotations and shell fences via dispatch table.
        for pattern, use_stripped, handler in _BLOCK_HANDLERS:
            text = line.strip() if use_stripped else line
            if pattern.match(text):
                i = handler(lines, i, blocks, state)
                break
        else:
            # No handler matched — non-empty lines reset the skip flag.
            if line.strip():
                state.skip_next = False
            i += 1

    return blocks


def build_script(input_path: Path, blocks: list[str]) -> str:
    """Assemble the final bash script from extracted blocks."""
    header = (
        "#!/bin/bash\n"
        f"# Extracted from : {input_path}\n"
        f"# Regenerate with: python3 extract_commands.py {input_path} <output.sh>\n"
        "#\n"
        "# Only ```shell fences are extracted; use any other tag to naturally"
        " exclude a block.\n"
        "\n"
        "set -euo pipefail\n"
        "\n"
        "# Load shared helpers (wait_idle, retry_until_success, etc.).\n"
        'HELPERS="${SPREAD_PATH:-$(cd "$(dirname "$0")" && pwd)}/helpers.sh"\n'
        '. "$HELPERS"\n'
        "\n"
    )
    return header + "\n\n".join(blocks) + "\n"


def extract_spread_meta(source: str) -> dict[str, str]:
    """Extract spread test metadata from a ``<!-- test:spread ... -->`` block."""
    lines = source.splitlines()
    for i, line in enumerate(lines):
        if _SPREAD_META_START.match(line.strip()):
            meta: dict[str, str] = {}
            j = i + 1
            while j < len(lines):
                raw = lines[j]
                if "-->" in raw:
                    break
                stripped = raw.strip()
                if stripped and ":" in stripped:
                    key, _, value = stripped.partition(":")
                    meta[key.strip()] = value.strip()
                j += 1
            return meta
    return {}


def extract_heading(source: str) -> str:
    """Return the text of the first Markdown heading."""
    for line in source.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return ""


def build_task_yaml(script_path: str, heading: str, meta: dict[str, str]) -> str:
    """Generate a Spread task.yaml file."""
    priority = meta.get("priority", "0")
    kill_timeout = meta.get("kill-timeout", "30m")
    summary = heading or script_path
    return (
        f'summary: "{summary}"\n'
        f"priority: {priority}\n"
        f"kill-timeout: {kill_timeout}\n"
        f"execute: |\n"
        f'  bash "$SPREAD_PATH/{script_path}"\n'
    )


def _process_pair(input_path: Path, output_path: Path) -> None:
    """Extract shell blocks from *input_path* and write the script."""
    if not input_path.exists():
        sys.exit(f"Error: {input_path} does not exist")

    source = input_path.read_text(encoding="utf-8")
    blocks = extract_shell_blocks(source)

    if not blocks:
        print(f"Warning: no shell blocks found in {input_path}", file=sys.stderr)

    script = build_script(input_path, blocks)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(script, encoding="utf-8")
    print(f"Written {len(blocks)} block(s) → {output_path}")

    # Generate task.yaml alongside the .sh file if spread metadata exists.
    meta = extract_spread_meta(source)
    heading = extract_heading(source)
    if meta:
        task_dir = output_path.with_suffix("")  # environment.sh → environment/
        task_yaml = task_dir / "task.yaml"
        task_yaml.parent.mkdir(parents=True, exist_ok=True)
        task_content = build_task_yaml(str(output_path), heading, meta)
        task_yaml.write_text(task_content, encoding="utf-8")
        print(f"Written task.yaml → {task_yaml}")


def _discover_and_process(input_dir: Path, output_dir: Path) -> None:
    """Find all .md files with spread metadata and generate scripts.

    Only files containing a ``<!-- test:spread ... -->`` block are processed.
    The output filename is ``<stem>.sh`` where *stem* is the Markdown filename
    without the ``.md`` extension.
    """
    md_files = sorted(input_dir.glob("*.md"))
    if not md_files:
        sys.exit(f"Error: no .md files found in {input_dir}")

    processed = 0
    for md_file in md_files:
        source = md_file.read_text(encoding="utf-8")
        if not extract_spread_meta(source):
            continue
        output_path = output_dir / f"{md_file.stem}.sh"
        _process_pair(md_file, output_path)
        processed += 1

    if not processed:
        sys.exit(f"Error: no files with spread metadata found in {input_dir}")
    print(f"Processed {processed} file(s) from {input_dir}")


def main() -> None:
    args = sys.argv[1:]

    if not args:
        print(__doc__)
        sys.exit(1)

    # Directory mode: discover files with spread metadata automatically.
    if len(args) == 2 and Path(args[0]).is_dir():
        _discover_and_process(Path(args[0]), Path(args[1]))
        return

    # Single input with no output → print to stdout.
    if len(args) == 1:
        input_path = Path(args[0])
        if not input_path.exists():
            sys.exit(f"Error: {input_path} does not exist")
        source = input_path.read_text(encoding="utf-8")
        blocks = extract_shell_blocks(source)
        if not blocks:
            print(
                f"Warning: no shell blocks found in {input_path}", file=sys.stderr
            )
        print(build_script(input_path, blocks), end="")
        return

    # One or more <input.md> <output.sh> pairs.
    if len(args) % 2 != 0:
        sys.exit("Error: arguments must be pairs of <input.md> <output.sh>")

    for i in range(0, len(args), 2):
        _process_pair(Path(args[i]), Path(args[i + 1]))


if __name__ == "__main__":
    main()
