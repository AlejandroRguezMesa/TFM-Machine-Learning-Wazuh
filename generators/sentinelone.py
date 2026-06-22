"""
SentinelOne log generator.

IMPORTANTE: las reglas oficiales 300600 / 300610 / 300650 tienen <location>
hardcodeada con paths exactos:

    /var/log/sentinelone.json                  (threats)        → regla 300600
    /var/log/sentinelone_activities.json       (activities)     → regla 300610
    /var/log/sentinelone-device-control.json   (device control) → regla 300650

Si el localfile no tiene exactamente esos paths, la regla padre no dispara
y el resto de la cadena (300601, 300611, 300651...) tampoco se evalúa.

Una línea JSON por evento, sin prefijos.
"""
from __future__ import annotations
import json
import random
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass


def _ts_iso(ts: datetime) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class ActiveThreat:
    """Amenaza activa detectada por EDR. Regla 300601, level 10.

    Fichero destino: /var/log/sentinelone.json
    """
    computer_name: str = "DESKTOP-USER001"
    threat_name: str = "mimikatz.exe"
    file_path: str = "C:\\\\Users\\\\Public\\\\mimikatz.exe"
    file_sha1: str = "d3b07384d113edec49eaa6238ad5ff00"
    user_name: str = "LABCORP\\\\lab.user1"
    mitigation_mode: str = "detect"  # 'detect' dispara 300601; 'protect' es prevención
    classification: str = "Malware"

    def render(self, ts: datetime) -> str:
        payload = {
            "agentDetectionInfo": {
                "agentDetectionState": "full_disk_scan",
                "agentDomain": "LABCORP",
                "agentIpV4": "10.0.5.20",
                "agentLastLoggedInUserName": self.user_name,
                "agentMitigationMode": self.mitigation_mode,
                "agentOsName": "Windows 10 Enterprise",
                "agentRegisteredAt": _ts_iso(ts),
                "agentVersion": "23.4.4.223",
            },
            "agentRealtimeInfo": {
                "accountId": "1000000000000000000",
                "activeThreats": 1,
                "agentComputerName": self.computer_name,
                "agentDecommissionedAt": None,
                "agentDomain": "LABCORP",
                "agentId": str(random.randint(10**18, 10**19 - 1)),
                "agentInfected": True,
                "agentIsActive": True,
                "agentIsDecommissioned": False,
                "agentMachineType": "desktop",
                "agentOsType": "windows",
                "agentVersion": "23.4.4.223",
                "rebootRequired": False,
            },
            "threatInfo": {
                "analystVerdict": "undefined",
                "classification": self.classification,
                "classificationSource": "Engine",
                "confidenceLevel": "malicious",
                "createdAt": _ts_iso(ts),
                "fileExtensionType": "Executable",
                "filePath": self.file_path,
                "fileSize": 1024000,
                "fileVerificationType": "NotSigned",
                "identifiedAt": _ts_iso(ts),
                "initiatedBy": "agent_policy",
                "isFileless": False,
                "isValidCertificate": False,
                "mitigatedPreemptively": False,
                "mitigationStatus": "not_mitigated",
                "originatorProcess": "explorer.exe",
                "sha1": self.file_sha1,
                "threatId": str(uuid.uuid4()),
                "threatName": self.threat_name,
            },
        }
        return json.dumps(payload, separators=(",", ":"))


@dataclass
class MitigatedThreat:
    """Amenaza mitigada con éxito. Regla 300602, level 5."""
    computer_name: str = "DESKTOP-USER001"
    threat_name: str = "trojan.gen.npe"

    def render(self, ts: datetime) -> str:
        payload = {
            "agentDetectionInfo": {"agentMitigationMode": "protect"},
            "agentRealtimeInfo": {
                "agentComputerName": self.computer_name,
                "activeThreats": 0,
                "rebootRequired": False,
            },
            "threatInfo": {
                "threatName": self.threat_name,
                "mitigationStatus": "mitigated",
                "createdAt": _ts_iso(ts),
                "classification": "Trojan",
            },
        }
        return json.dumps(payload, separators=(",", ":"))


@dataclass
class UsbActivity:
    """Inserción/extracción de USB. Regla 300651, level 3.

    Fichero destino: /var/log/sentinelone-device-control.json
    """
    computer_name: str = "DESKTOP-USER001"
    device_name: str = "Kingston DataTraveler 3.0"
    event_type: str = "Inserted"  # Inserted | Ejected
    interface: str = "USB"

    def render(self, ts: datetime) -> str:
        payload = {
            "computerName": self.computer_name,
            "deviceName": self.device_name,
            "interface": self.interface,
            "eventType": self.event_type,
            "eventTime": _ts_iso(ts),
            "eventId": str(random.randint(10**8, 10**9 - 1)),
            "uuid": str(uuid.uuid4()),
            "vendorId": "0951",
            "productId": "1666",
        }
        return json.dumps(payload, separators=(",", ":"))


@dataclass
class ConsoleLogin:
    """Login a la consola Singularity de SentinelOne. Regla 300612, level 4."""
    user_email: str = "soc.analyst@labcorp.local"
    primary_description: str = "The management user soc.analyst@labcorp.local logged in to console."

    def render(self, ts: datetime) -> str:
        payload = {
            "id": str(random.randint(10**18, 10**19 - 1)),
            "activityType": 27,
            "primaryDescription": self.primary_description,
            "secondaryDescription": "",
            "createdAt": _ts_iso(ts),
            "userEmail": self.user_email,
            "data": {"username": self.user_email},
        }
        return json.dumps(payload, separators=(",", ":"))


# Ruido benigno
NOISE_HOSTS = [f"DESKTOP-USER{i:03d}" for i in range(40)]
NOISE_ANALYSTS = [
    "soc.analyst@labcorp.local",
    "secops.lead@labcorp.local",
    "ti.team@labcorp.local",
]


def noise_console_login(ts: datetime) -> str:
    user = random.choice(NOISE_ANALYSTS)
    return ConsoleLogin(
        user_email=user,
        primary_description=f"The management user {user} logged in to console.",
    ).render(ts)


def noise_usb_eject(ts: datetime) -> str:
    return UsbActivity(
        computer_name=random.choice(NOISE_HOSTS),
        device_name="Logitech USB Receiver",
        event_type="Ejected",
    ).render(ts)
