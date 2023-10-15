#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.
import json
import logging
import subprocess
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pytest_operator.plugin import OpsTest
from tenacity import RetryError, Retrying, stop_after_delay, wait_fixed

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)s", datefmt="%H:%M:%S"
)
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

    def dump(self) -> Dict[str, Any]:
        """To json."""
        result = {}
        for key, val in vars(self).items():
            result[key] = vars(val) if isinstance(val, Status) else val
        return result


def get_raw_application(ops_test: OpsTest, app: str) -> Dict[str, Any]:
    """Get raw application details."""
    return json.loads(
        subprocess.check_output(
            f"juju status --model {ops_test.model.info.name} {app} --format=json".split()
        )
    )["applications"][app]


def now() -> str:
    """Print date."""
    return datetime.now().strftime("%H:%M:%S")


def _dump_juju_logs(model: str, unit: Optional[str] = None, lines: int = 500) -> None:
    """Dump juju logs on the console."""
    target_file = f"/tmp/{uuid4().hex}.txt"

    cmd = "juju debug-log"
    if unit:
        cmd = f"{cmd} --include={unit.replace('-', '/')}"
    cmd = f"{cmd} --model={model} -n {lines} > {target_file}; cat {target_file}"
    logger.error(f"Dumping juju logs for {unit if unit else 'all'}:")
    logger.error(subprocess.check_output(cmd, shell=True).decode("utf-8"))
    logger.error("\n\n")


def _progress_line(units: List[Unit]) -> str:
    """Log progress line."""
    log = ""
    for u in units:
        if not log:
            log = (
                f"\n\tapp: {u.name.split('-')[0]} {u.app_status.value} -- "
                f"message: {u.app_status.message}\n"
            )

        log = (
            f"{log}\t\t{u.name}{'*' if u.is_leader else ' '} -- ({u.ip}) -- [{u.agent_status.value} "
            f"(since: {u.agent_status.since.strftime('%H:%M:%S')})] "
            f"{u.workload_status.value}: {u.workload_status.message or ''}\n"
        )

    return log


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

        if not unit.get("public-address"):
            # unit not ready yet...
            continue

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
                value=unit["juju-status"]["current"],
                since=unit["juju-status"]["since"],
            ),
            app_status=Status(
                value=raw_app["application-status"]["current"],
                since=raw_app["application-status"]["since"],
                message=raw_app["application-status"].get("message"),
            ),
        )

        units.append(unit)

    return units


def _is_every_condition_on_app_met(
    ops_test: OpsTest,
    app: str,
    units: Optional[List[Unit]],
    apps_statuses: Optional[List[str]],
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]],
) -> bool:
    """Evaluate if all the conditions of an application are met."""
    if units:
        app_status = units[0].app_status
    else:
        app_status = get_raw_application(ops_test, app)["application-status"]
        app_status = Status(
            value=app_status["current"],
            since=app_status["since"],
            message=app_status.get("message"),
        )

    if apps_statuses:
        if app_status.value not in apps_statuses:
            return False
    else:
        any_match = False
        for status_val, messages in apps_full_statuses[app].items():
            any_match = any_match or (
                app_status.value == status_val and app_status.message in (messages or ["", None])
            )
        if not any_match:
            return False

    return True


def _is_every_condition_on_units_met(
    model: str,
    app: str,
    units: List[Unit],
    units_statuses: Optional[List[str]],
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]],
    idle_period: int,
) -> bool:
    """Evaluate if all the conditions of a unit are met."""
    for unit in units:
        if unit.agent_status.value != "idle":
            return False

        if unit.workload_status.value == "error":
            logger.error(f"Error in: {unit.name}")
            _dump_juju_logs(model, unit.name)

        if units_statuses:
            if unit.workload_status.value not in units_statuses:
                return False
        else:
            any_match = False
            for status_val, messages in units_full_statuses[app]["units"].items():
                any_match = any_match or (
                    unit.workload_status.value == status_val
                    and unit.workload_status.message in (messages or ["", None])
                )
            if not any_match:
                return False

        if unit.agent_status.since + timedelta(seconds=idle_period) > datetime.now():
            return False

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
        expected_units = wait_for_exact_units[app]
        units = await get_application_units(ops_test, app)
        if -1 < expected_units != len(units):
            logger.info(f"{app} -- expected units: {expected_units} -- current: {len(units)}")
            return False

        if (apps_statuses or apps_full_statuses) and not _is_every_condition_on_app_met(
            ops_test=ops_test,
            app=app,
            units=(units if expected_units > -1 else None),
            apps_statuses=apps_statuses,
            apps_full_statuses=apps_full_statuses,
        ):
            logger.info(f"\tApp: {app} - conditions unmet.")
            logger.info(_progress_line(units))
            return False

        if (
            expected_units > -1
            and (units_statuses or units_full_statuses)
            and not _is_every_condition_on_units_met(
                model=ops_test.model.info.name,
                app=app,
                units=units,
                units_statuses=units_statuses,
                units_full_statuses=units_full_statuses,
                idle_period=idle_period,
            )
        ):
            logger.info(f"\tApp: {app} - Units - conditions unmet.")
            logger.info(_progress_line(units))
            return False

    return True


async def wait_until(  # noqa: C901
    ops_test: OpsTest,
    apps: List[str],
    apps_statuses: Optional[List[str]] = None,
    apps_full_statuses: Optional[Dict[str, Dict[str, List[str]]]] = None,
    units_statuses: Optional[List[str]] = None,
    units_full_statuses: Optional[Dict[str, Dict[str, Dict[str, List[str]]]]] = None,
    wait_for_exact_units: Optional[Union[int, Dict[str, int]]] = -1,
    idle_period: int = 30,
    timeout: int = 1200,
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
        wait_for_exact_units: The desired number of units to wait for, can be >= to -1
            if set as int, this value is expected for all apps but if more granularity is needed to
            be set, pass a dictionary such as: {"app1": 2, "app2": 1, ...}, if set to -1, the check
            only happens at the application level.
        idle_period: Seconds to wait for the agents of each application unit to be idle.
        timeout: Time to wait before giving up on waiting.
    """
    if not apps:
        raise ValueError("apps must be specified.")

    if not (apps_statuses or apps_full_statuses or units_statuses or units_full_statuses):
        apps_statuses = ["active"]
        units_statuses = ["active"]

    if isinstance(wait_for_exact_units, int):
        wait_for_exact_units = {app: wait_for_exact_units for app in apps}
    elif not wait_for_exact_units:
        wait_for_exact_units = {app: -1 for app in apps}
    else:
        for app in apps:
            if app not in wait_for_exact_units:
                wait_for_exact_units[app] = 1

    try:
        logger.info("\n\n\n")
        logger.info(
            subprocess.check_output(
                f"juju status --model {ops_test.model.info.name}", shell=True
            ).decode("utf-8")
        )

        for attempt in Retrying(stop=stop_after_delay(timeout), wait=wait_fixed(10)):
            with attempt:
                logger.info(f"\n\n\n{now()} -- Waiting for model...")
                if await _is_every_condition_met(
                    ops_test=ops_test,
                    apps=apps,
                    wait_for_exact_units=wait_for_exact_units,
                    apps_statuses=apps_statuses,
                    apps_full_statuses=apps_full_statuses,
                    units_statuses=units_statuses,
                    units_full_statuses=units_full_statuses,
                    idle_period=idle_period,
                ):
                    logger.info(f"{now()} -- Waiting for model: complete.\n\n\n")
                    return

                raise Exception
    except RetryError:
        logger.error("wait_until -- Timed out!\n\n\n")
        logger.info(
            subprocess.check_output(
                f"juju status --model {ops_test.model.info.name}", shell=True
            ).decode("utf-8")
        )
        _dump_juju_logs(model=ops_test.model.info.name, lines=3000)
        raise
