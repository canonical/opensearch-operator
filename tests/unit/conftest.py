# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict

import pytest
import yaml
from ops import testing

from src.charm import OpenSearchOperatorCharm


@pytest.fixture(autouse=True)
def with_juju_secrets(monkeypatch):
    monkeypatch.setattr("ops.JujuVersion.has_secrets", True)


def _load_yaml(path: str) -> Dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    data = yaml.safe_load(p.read_text()) or {}
    return data if isinstance(data, dict) else {}


_METADATA = _load_yaml("metadata.yaml")
_CONFIG_SCHEMA = _load_yaml("config.yaml")
_ACTIONS = _load_yaml("actions.yaml")


@pytest.fixture
def metadata() -> Dict[str, Any]:
    return deepcopy(_METADATA)


@pytest.fixture
def charm_config() -> Dict[str, Any]:
    return deepcopy(_CONFIG_SCHEMA)


@pytest.fixture
def actions() -> Dict[str, Any]:
    return deepcopy(_ACTIONS)


@pytest.fixture
def mk_ctx(monkeypatch):
    def _mk(meta: dict, actions: dict, cfg_schema: dict, unit_id: int = 0):
        ctx = testing.Context(
            charm_type=OpenSearchOperatorCharm,
            meta=meta,
            actions=actions,
            config=cfg_schema,
            unit_id=unit_id,
            capture_deferred_events=True,
        )
        results_holder: Dict[str, Any] = {}

        def _set_results(self, mapping: Dict[str, Any]):
            results_holder.clear()
            results_holder.update(mapping or {})

        monkeypatch.setattr("ops.charm.ActionEvent.set_results", _set_results, raising=True)

        def _run(ev, st: testing.State):
            ctx.run(ev, st)

        return SimpleNamespace(
            on=ctx.on,
            run=_run,
            action_results=results_holder,
        )

    return _mk
