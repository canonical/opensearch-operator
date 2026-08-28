# Upgrade guide end-to-end tests

This directory contains the end-to-end test harness for
[`docs/how-to/upgrade.md`](../../../docs/how-to/upgrade.md). It uses the same
approach as the tutorial tests (`tests/tutorial/`): shell commands are
extracted from the Markdown guide and executed as Spread tasks inside a
Multipass VM.

Unlike the tutorial, the upgrade guide is split into **multiple tasks** that
run sequentially in a single VM, covering every logic branch of the guide:

| Task | Priority | Covers |
| ---- | -------- | ------ |
| `bootstrap` (hand-written) | 900 | Environment setup, revision resolution, baseline deployment, seed index |
| `upgrade-happy-path` | 800 | Scale-up, `pre-upgrade-check`, `juju refresh`, `resume-upgrade`, scale-back, health check |
| `rollback-same-workload` | 700 | Mid-upgrade rollback to a revision with the same workload version |
| `rollback-different-workload` | 600 | Rollback to a different workload version, `force-refresh-start check-compatibility=false` |
| `recover-from-rollback` | 500 | Orphaned index deletion, allocation settings, unit replacement, node-lock removal |

Teardown is implicit: Spread's `discard` phase purges the whole Multipass VM
(`opensearch-upgrade-vm`), so no explicit cleanup task is needed.

## Running

From the project root:

```bash
tox -e guide-upgrade            # full suite via Spread (requires Multipass + Spread)
tox -e guide-upgrade-extract    # only regenerate the task scripts
```

Or directly:

```bash
make -f tests/guides/upgrade/Makefile test         # abort on first failure
make -f tests/guides/upgrade/Makefile test-continue # run all tasks
make -f tests/guides/upgrade/Makefile test-debug    # shell on failure
```

## How it works

`extract_guide_tasks.py` parses the guide and emits one shell script per task
into `tasks/`, plus a `task.yaml` for Spread. Task boundaries are declared in
the guide's existing `<!-- test:spread ... -->` metadata block — no extra
inline markers and no page split:

```
<!-- test:spread
kill-timeout: 90m
tasks:
  - name: upgrade-happy-path
    from: how-to-minor-upgrade        # MyST anchor or heading text
    to:   how-to-minor-rollback
    priority: 800
-->
```

If a `from`/`to` reference no longer resolves (e.g. a heading was renamed),
extraction fails loudly — this guards against silent test drift.

### Annotations

All annotations are HTML comments and never render in the published docs.

| Annotation | Purpose |
| ---------- | ------- |
| `<!-- test:spread ... -->` | Task metadata + `tasks:` partition list |
| `<!-- test:vars ... -->` | Map placeholders (`<target-revision>`) to literals or `${VAR}` references |
| `<!-- test:setup ... -->` | Hidden commands emitted before the task body (state resets) |
| `<!-- test:teardown ... -->` | Hidden commands emitted after the task body |
| `<!-- test:run ... -->` | Hidden commands emitted inline |
| `<!-- test:assert ... -->` | Hidden assertion commands (fail the task on non-zero exit) |
| `<!-- test:await-idle ... -->` | Wait for all Juju units to settle |
| `<!-- test:skip -->` | Skip the next ```shell block (e.g. local `.charm` file paths) |
| `<!-- test:wait --seconds N -->` | Plain sleep |
| `<!-- test:retry ... -->` | Retry a command until success |

The guide itself stays generic: concrete values (revisions, unit IPs,
passwords) are injected through `test:vars` and hidden `test:run` blocks.

## Revision resolution

`resolve_revisions.py` queries the Charmhub API at test time and picks:

- `REV_TO` — latest `2/stable` revision
- `REV_FROM_SAME` — highest revision with the same workload version (for the
  same-workload rollback)
- `REV_FROM_DIFF` — highest revision with an older workload version (for the
  different-workload rollback)

If the API cannot yield a suitable pair, a pinned fallback in
`PINNED_FALLBACK` is used and a loud warning is printed — refresh the pins
when that happens.

## Helpers

`helpers.sh` provides `wait_idle`, `retry_until_success` (from the tutorial
harness) plus upgrade-specific helpers: `current_revision`,
`wait_app_status`, `wait_unit_message`, `save_ca_and_password`, and
`cluster_health`.
