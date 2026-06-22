"""
vCenter log generator.

Formato exacto extraído del full_log real:

    1 2026-05-12T01:00:04.189483+01:00 vc1 vpxd 6707 - -  Event [118585496] [1-1] \
        [2026-05-12T00:00:04.188416Z] [vim.event.UserLogoutSessionEvent] [info] \
        [VSPHERE.LOCAL\\svc-snapcenter] [] [118585496] [User VSPHERE.LOCAL\\svc-snapcenter@10.252.11.47 logged out ...]

Estructura:  1 <iso+TZ> <host> <proc> <pid> - -  Event [eid] [1-1] [<isoZ>] [<class>] [<level>] [<user>] [<empty>] [eid] [<descripcion>]
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass

HOST = "vc1"
PROC = "vpxd"
PID = 6707
EVENT_ID_START = 118585496

_event_counter = EVENT_ID_START


def _next_eid() -> int:
    global _event_counter
    _event_counter += random.randint(1, 6)
    return _event_counter


def _iso_local(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+01:00"


def _iso_utc(ts: datetime) -> str:
    utc = ts - timedelta(hours=1)  # asumimos host en +01:00
    return utc.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _envelope(ts: datetime, eid: int, class_name: str, level: str,
              vc_user: str, principal: str, description: str) -> str:
    return (
        f"1 {_iso_local(ts)} {HOST} {PROC} {PID} - -  "
        f"Event [{eid}] [1-1] [{_iso_utc(ts)}] [{class_name}] [{level}] "
        f"[{vc_user}] [{principal}] [{eid}] [{description}]"
    )


@dataclass
class LoginEvent:
    """Login a vCenter — dispara regla 140007."""
    user: str = "VSPHERE.LOCAL\\administrator"
    src_ip: str = "10.252.11.47"
    user_agent: str = "VMware vim-java 1.0"

    def render(self, ts: datetime) -> str:
        eid = _next_eid()
        desc = (f"User {self.user}@{self.src_ip} logged in as {self.user_agent}")
        return _envelope(ts, eid, "vim.event.UserLoginSessionEvent",
                         "info", self.user, "", desc)


@dataclass
class LogoutEvent:
    user: str = "VSPHERE.LOCAL\\administrator"
    src_ip: str = "10.252.11.47"

    def render(self, ts: datetime) -> str:
        eid = _next_eid()
        login_h = ts - timedelta(minutes=random.randint(5, 240))
        desc = (f"User {self.user}@{self.src_ip} logged out "
                f"(login time: {login_h.strftime('%A, %d %B, %Y %I:%M:%S %p')}, "
                f"number of API invocations: 0, user agent: Java/11.0.26)")
        return _envelope(ts, eid, "vim.event.UserLogoutSessionEvent",
                         "info", self.user, "", desc)


@dataclass
class TaskEvent:
    """Tareas vCenter (clones, vmotion, snapshots). Dispara regla 140006."""
    user: str = "VSPHERE.LOCAL\\svc-vsc"
    task_name: str = "ONTAP tools Discover hosts"

    def render(self, ts: datetime) -> str:
        eid = _next_eid()
        desc = f"Task: {self.task_name}"
        return _envelope(ts, eid, "vim.event.TaskEvent", "info",
                         self.user, "", desc)


@dataclass
class AlarmEvent:
    """Alarmas de monitorización (dispara 140009 normalmente nivel 3)."""
    alarm_name: str = "Virtual machine CPU usage"
    host: str = "SRVGSA03"
    from_state: str = "Green"
    to_state: str = "Yellow"

    def render(self, ts: datetime) -> str:
        eid = _next_eid()
        desc = f"Alarm '{self.alarm_name}' on {self.host} changed from {self.from_state} to {self.to_state}"
        return _envelope(ts, eid, "vim.event.AlarmStatusChangedEvent",
                         "info", "", "Principal", desc)


@dataclass
class VmotionEvent:
    """Migración vMotion entre hosts ESXi."""
    vm: str = "LABCORP Sentinelone"
    src_host_id: str = "host-22928"
    dst_host_id: str = "host-73470"
    src_ip: str = "10.252.11.247"
    dst_ip: str = "10.252.11.251"

    def render(self, ts: datetime) -> str:
        eid = _next_eid()
        desc = (f"Local-VC Host Migrate of poweredOn VM '{self.vm}' "
                f"on {self.src_host_id} ({self.src_ip}) to "
                f"{self.dst_host_id} ({self.dst_ip})")
        return _envelope(ts, eid, "vim.event.EventEx", "info",
                         "VSPHERE.LOCAL\\svc-vmotion", "", desc)


# Ruido benigno
NOISE_USERS = [
    "VSPHERE.LOCAL\\svc-snapcenter",
    "VSPHERE.LOCAL\\svc-vsc",
    "VSPHERE.LOCAL\\svc-hcx",
    "VSPHERE.LOCAL\\svc-vmotion",
    "root@127.0.0.1",
]
NOISE_TASKS = [
    "Recompute virtual disk digest information",
    "Update virtual machine files",
    "Collect VM performance stats",
    "ONTAP tools Discover hosts",
    "HostProfileApply",
]
NOISE_ALARMS = [
    ("Virtual machine CPU usage", "Green", "Yellow"),
    ("Datastore usage on disk", "Yellow", "Green"),
    ("Host memory usage", "Green", "Yellow"),
]


def noise_login(ts: datetime) -> str:
    return LoginEvent(user=random.choice(NOISE_USERS),
                      src_ip=f"10.252.11.{random.randint(40, 70)}").render(ts)


def noise_logout(ts: datetime) -> str:
    return LogoutEvent(user=random.choice(NOISE_USERS),
                       src_ip=f"10.252.11.{random.randint(40, 70)}").render(ts)


def noise_task(ts: datetime) -> str:
    return TaskEvent(user=random.choice(NOISE_USERS),
                     task_name=random.choice(NOISE_TASKS)).render(ts)


def noise_alarm(ts: datetime) -> str:
    name, frm, to = random.choice(NOISE_ALARMS)
    return AlarmEvent(alarm_name=name,
                      host=f"SRVGSA{random.randint(1, 20):02d}",
                      from_state=frm, to_state=to).render(ts)
