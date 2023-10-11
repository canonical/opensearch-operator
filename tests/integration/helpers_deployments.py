#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union

from pytest_operator.plugin import OpsTest

logger = logging.getLogger(__name__)


class Status:
    """Model class for status."""

    def __init__(self, value: str, since: str, message: Optional[str] = None):
        self.value = value
        self.since = datetime.strptime(since, "%d %b %Y %H:%M:%SZ")
        self.message = message


class Unit:
    """Model class for a Unit, with properties widely used."""

    def __init__(
        self,
        id: int,
        name: str,
        ip: str,
        hostname: str,
        is_leader: bool,
        machine_id: int,
        workload_status: Status,
        agent_status: Status,
        app_status: Status,
    ):
        self.id = id
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.is_leader = is_leader
        self.machine_id = machine_id
        self.workload_status = workload_status
        self.agent_status = agent_status
        self.app_status = app_status


def get_raw_application(ops_test: OpsTest, app: str) -> Dict[str, Any]:
    """Get raw application details."""
    return json.loads(
        subprocess.check_output(
            f"juju status --model {ops_test.model.info.name} {app} --format=json".split()
        )
    )["applications"][app]


async def get_unit_hostname(ops_test: OpsTest, unit_id: int, app: str) -> str:
    """Get the hostname of a specific unit."""
    _, hostname, _ = await ops_test.juju("ssh", f"{app}/{unit_id}", "hostname")
    return hostname.strip()


async def get_application_units(ops_test: OpsTest, app: str) -> List[Unit]:
    """Get fully detailed units of an application."""
    # Juju incorrectly reports the IP addresses after the network is restored this is reported as a
    # bug here: https://github.com/juju/python-libjuju/issues/738. Once this bug is resolved use of
    # `get_unit_ip` should be replaced with `.public_address`
    raw_app = get_raw_application(ops_test, app)

    units = []
    for u_name, unit in raw_app["units"].items():
        unit_id = int(u_name.split("/")[-1])
        unit = Unit(
            id=unit_id,
            name=u_name.replace("/", "-"),
            ip=unit["public-address"],
            hostname=await get_unit_hostname(ops_test, unit_id, app),
            is_leader=unit.get("leader", False),
            machine_id=int(unit["machine"]),
            workload_status=Status(
                value=unit["workload-status"]["current"],
                since=unit["workload-status"]["since"],
                message=unit["workload-status"].get("message"),
            ),
            agent_status=Status(
                value=unit["agent-status" if "agent-status" in unit else "workload-status"][
                    "current"
                ],
                since=unit["agent-status" if "agent-status" in unit else "workload-status"][
                    "since"
                ],
            ),
            app_status=Status(
                value=raw_app["application-status"]["current"],
                since=raw_app["application-status"]["since"],
                message=raw_app["application-status"].get("message"),
            ),
        )
        units.append(unit)

    return units


async def _is_every_condition_on_app_met(
    ops_test: OpsTest,
    app: str,
    units: List[Unit],
    apps_statuses: Optional[List[str]],
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]],
    idle_period: int,
) -> bool:
    """Evaluate if all the conditions of an application are met."""
    if units:
        app_status = units[0].app_status
    else:
        app_status = get_raw_application(ops_test, app)["application-status"]
        app_status = Status(
            value=app_status["value"], since=app_status["since"], message=app_status["message"]
        )

    if apps_statuses:
        if app_status.value not in apps_statuses:
            logger.info(
                f"UNMET - app: {app} -- app_status: {app_status.value} not in expected: {apps_statuses}"
            )
            return False
    else:
        any_match = False
        for status_val, messages in apps_full_statuses[app].items():
            logger.info(
                f"app: {app} -- app_status: {app_status.value} vs {status_val} and message: {app_status.message} vs {messages or ['', None]}"
            )
            any_match = any_match or (
                app_status.value == status_val and app_status.message in (messages or ["", None])
            )
        if not any_match:
            logger.info(f"UNMET - app: {app} -- app_full_statuses")
            return False

    if app_status.since + timedelta(seconds=idle_period) > datetime.now():
        logger.info(f"UNMET - app: {app} -- app_status.since: {app_status.since} < {idle_period}")
        return False

    logger.info(f"MET - app: {app}")
    return True


async def _is_every_condition_on_units_met(
    app: str,
    units: List[Unit],
    units_statuses: Optional[List[str]],
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]],
    idle_period: int,
) -> bool:
    """Evaluate if all the conditions of a unit are met."""
    for unit in units:
        if unit.agent_status != "idle":
            logger.info(f"UNMET - unit: {unit.name} -- agent_status: {unit.agent_status}")
            return False

        if units_statuses:
            if unit.workload_status.value not in units_statuses:
                logger.info(
                    f"UNMET - unit: {unit.name} -- workload_status: {unit.workload_status.value} not in expected: {units_statuses}"
                )
                return False
        else:
            any_match = False
            for status_val, messages in units_full_statuses[app]["units"].items():
                logger.info(
                    f"unit: {unit.name} -- workload_status: {unit.workload_status.value} vs {status_val} and message: {unit.workload_status.message} vs {messages or ['', None]}"
                )
                any_match = any_match or (
                    unit.workload_status.value == status_val
                    and unit.workload_status.message in (messages or ["", None])
                )
            if not any_match:
                logger.info(f"UNMET - unit: {unit.name} -- unit_full_statuses")
                return False

        if unit.agent_status.since + timedelta(seconds=idle_period) > datetime.now():
            logger.info(
                f"UNMET - unit: {unit.name} -- agent_status.since: {unit.agent_status.since} < {idle_period}"
            )
            return False

    logger.info("MET - all units")
    return True


async def _is_every_condition_met(
    ops_test: OpsTest,
    apps: List[str],
    wait_for_exact_units: Dict[str, int],
    apps_statuses: Optional[List[str]] = None,
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]] = None,
    units_statuses: Optional[List[str]] = None,
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]] = None,
    idle_period: int = 30,
) -> bool:
    """Evaluate if all the deployment status conditions are met."""
    for app in apps:
        units = await get_application_units(ops_test, app)
        if len(units) != wait_for_exact_units[app]:
            logger.info(
                f"UNMET - app: {app} -- len(units): {len(units)} vs expected: {wait_for_exact_units[app]}"
            )
            return False

        if (apps_statuses or apps_full_statuses) and not _is_every_condition_on_app_met(
            ops_test, app, units, apps_statuses, apps_full_statuses, idle_period
        ):
            return False

        if (units_statuses or units_full_statuses) and not _is_every_condition_on_units_met(
            app, units, units_statuses, units_full_statuses, idle_period
        ):
            return False

    logger.info("MET - everything!")
    return True


async def wait_until(
    ops_test: OpsTest,
    apps: List[str],
    apps_statuses: Optional[List[str]] = None,
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]] = None,
    units_statuses: Optional[List[str]] = None,
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]] = None,
    wait_for_exact_units: Optional[Union[int, Dict[str, int]]] = 1,
    idle_period: int = 30,
    timeout: int = 1000,
) -> None:
    """Block and wait until a set of statuses and timeouts are met.

    Args:
        ops_test: The ops test framework instance
        apps: A list of applications whose statuses to test against
        apps_statuses: List of acceptable application statuses to wait for, for all apps.
            ["blocked", "active", ...]
        apps_full_statuses: List of acceptable unit statuses to wait for, for all apps with more
            granularity: {"app1": {"blocked": ["msg1", "msg2"], "active": []}, "app2": ...}
        units_statuses: List of acceptable statuses to wait for, for all units of all apps.
            ["blocked", "active", ...]
        units_full_statuses: List of acceptable statuses to wait for, for all apps with more
            granularity: {"app1": "units": {"blocked": ["msg1", "msg2"], "active": []}}, "app2"...}
        wait_for_exact_units: The desired number of units to wait for, can be greater or equal to 0
            if set as int, this value is expected for all apps, if more granularity needed set as
            dictionary such as: {"app1": 2, "app2": 1, ...}
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        timeout: Time to wait for application to become stable.
    """
    if not apps:
        raise ValueError("apps must be specified.")

    if not (apps_statuses or apps_full_statuses or units_statuses or units_full_statuses):
        apps_statuses = ["active"]
        units_statuses = ["active"]

    if isinstance(wait_for_exact_units, int):
        wait_for_exact_units = {app: wait_for_exact_units for app in apps}
    elif not wait_for_exact_units:
        wait_for_exact_units = {app: 1 for app in apps}
    else:
        for app in apps:
            if app not in wait_for_exact_units:
                wait_for_exact_units[app] = 1

    await ops_test.model.block_until(
        lambda: _is_every_condition_met(
            ops_test=ops_test,
            apps=apps,
            wait_for_exact_units=wait_for_exact_units,
            apps_statuses=apps_statuses,
            apps_full_statuses=apps_full_statuses,
            units_statuses=units_statuses,
            units_full_statuses=units_full_statuses,
            idle_period=idle_period,
        ),
        timeout=timeout,
        wait_period=5,
    )
