"""
PaloAlto log generator.

Genera líneas en el formato que coincide EXACTAMENTE con full_log de tus alertas reales:

    May 12 01:00:00 PA-VM300-01.labcorp.local 1,2026/05/12 01:00:00,007951000469799,TRAFFIC,drop,...

El predecoder syslog de Wazuh extrae 'Mon DD HH:MM:SS' + hostname,
y el decoder paloalto matchea el resto (CSV).

NO añadir timestamp adicional ni eliminar la cabecera: el formato es el que es.
"""
from __future__ import annotations
import random
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional

HOSTNAME = "PA-VM300-01.labcorp.local"
SERIAL = "007951000469799"
DEVICE = "PA-VM300-01"
VSYS = "vsys1"


def _bsd_ts(ts: datetime) -> str:
    """Formato 'May 12 01:00:00' (BSD syslog)."""
    # locale-independent month abbrev
    months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
    return f"{months[ts.month - 1]} {ts.day:>2} {ts.strftime('%H:%M:%S')}"


def _pa_ts(ts: datetime) -> str:
    return ts.strftime("%Y/%m/%d %H:%M:%S")


def _iso_hr(ts: datetime) -> str:
    """High resolution timestamp con offset +01:00."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S") + f".{ts.microsecond // 1000:03d}+01:00"


@dataclass
class TrafficEvent:
    """Evento TRAFFIC de Palo Alto (rule 64508 dispara con action='drop')."""
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 53
    src_zone: str = "Hosting-Lab-Pre-IOT-Etc"
    dst_zone: str = "Hosting-Lab-Pre-IOT-Etc"
    rule_name: str = "Drop trafico interno Lab"
    action: str = "drop"
    application: str = "not-applicable"
    protocol: str = "udp"
    bytes_total: int = 75
    packets: int = 1
    session_id: int = 0
    src_user: str = ""
    src_country: str = "10.0.0.0-10.255.255.255"
    dst_country: str = "United States"
    inbound_if: str = "ethernet1/7.2220"

    def render(self, ts: datetime) -> str:
        ts_pa = _pa_ts(ts)
        ts_start = _pa_ts(ts - timedelta(seconds=2))
        seq = random.randint(7600058074500000000, 7600058074599999999)
        uuid = "3ea2ad5a-6547-45d8-8f03-c1102e8e346f"
        # Campos en orden EXACTO esperado por decoder paloalto-traffic-fields
        payload = (
            f"1,{ts_pa},{SERIAL},TRAFFIC,{self.action},2818,{ts_pa},"
            f"{self.src_ip},{self.dst_ip},0.0.0.0,0.0.0.0,{self.rule_name},"
            f"{self.src_user},,{self.application},{VSYS},{self.src_zone},{self.dst_zone},"
            f"{self.inbound_if},,Sent-Email-Syslog-Alarm,{ts_pa},{self.session_id},1,"
            f"{self.src_port},{self.dst_port},0,0,0x0,{self.protocol},{self.action},"
            f"{self.bytes_total},{self.bytes_total},0,{self.packets},{ts_start},0,any,,"
            f"{seq},0x0,{self.src_country},{self.dst_country},,1,0,policy-deny,"
            f"0,0,0,0,,{DEVICE},from-policy,,,0,,0,,N/A,0,0,0,0,{uuid},0,0,"
            f",,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,{_iso_hr(ts)},"
            f",,unknown,unknown,unknown,1,,,not-applicable,no,no,0,NonProxyTraffic,"
            f",no,0,0,0,0,0,0,0,0,0,0"
        )
        return f"{_bsd_ts(ts)} {HOSTNAME} {payload}"


@dataclass
class ThreatEvent:
    """Evento THREAT (URL filtering, vulnerability, etc.). Reglas 64500+."""
    src_ip: str
    dst_ip: str
    src_user: str = ""
    threat_name: str = "policy-deny"
    severity: str = "informational"
    category: str = "computer-and-internet-info"
    url: str = "euce1-labcorp.sentinelone.net/"
    action: str = "alert"
    threat_subtype: str = "url"  # url, vulnerability, spyware, virus, wildfire

    def render(self, ts: datetime) -> str:
        ts_pa = _pa_ts(ts)
        seq = random.randint(7600058073000000000, 7600058073999999999)
        payload = (
            f"1,{ts_pa},{SERIAL},THREAT,{self.threat_subtype},2818,{ts_pa},"
            f"{self.src_ip},18.197.147.66,192.168.3.1,18.197.147.66,"
            f"Navegacion Hosting-LabCorp,{self.src_user},,sentinelone,{VSYS},"
            f"Hosting-LabCorp,Untrust-IDECNET,ethernet1/7.2013,ethernet1/9.800,"
            f"Sent-Email-Syslog-Alarm,{ts_pa},85671,1,57685,443,13873,443,"
            f"0x42b400,tcp,{self.action},\"{self.url}\",(9999),{self.category},"
            f"{self.severity},client-to-server,{seq},0x0,"
            f"10.0.0.0-10.255.255.255,Germany,,,0,,,0,,,,,,,,0,0,0,0,0,,"
            f"{DEVICE},,,,,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,"
            f",\" allow-SentinelOne,{self.category},low-risk\","
            f"1f3d6507-5464-4afe-9abc-6f464d2e503b,0,,,,,,,,,,,,,,,,,,,,,,,,"
            f",,,,,0,{_iso_hr(ts)},,,,management,business-systems,client-server,"
            f"1,,,sentinelone,no,no,,,NonProxyTraffic,,false,0,0,,,,0"
        )
        return f"{_bsd_ts(ts)} {HOSTNAME} {payload}"


# Generadores de ruido (tráfico benigno típico)
NOISE_USERS = [f"labcorp\\lab.user{i:03d}" for i in range(40)]
NOISE_INT_IPS = [f"10.252.1.{i}" for i in range(20, 200)]
NOISE_EXT_IPS = ["8.8.8.8", "1.1.1.1", "142.250.78.78", "151.101.1.140",
                 "13.107.6.152", "20.190.144.131", "52.96.7.18"]


def noise_traffic_allow(ts: datetime) -> str:
    """Tráfico saliente normal permitido (no alerta crítica)."""
    ev = TrafficEvent(
        src_ip=random.choice(NOISE_INT_IPS),
        dst_ip=random.choice(NOISE_EXT_IPS),
        src_port=random.randint(30000, 60000),
        dst_port=random.choice([443, 80, 53, 123]),
        src_zone="DMZ4-Panorama",
        dst_zone="Untrust-Vodafone",
        rule_name="allow-outbound-web",
        action="allow",
        application=random.choice(["ssl", "web-browsing", "dns", "ntp"]),
        protocol=random.choice(["tcp", "udp"]),
        bytes_total=random.randint(500, 50000),
        packets=random.randint(2, 50),
        src_user=random.choice(NOISE_USERS),
    )
    return ev.render(ts)
