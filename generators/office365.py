"""
Office 365 log generator.

Schema esperado por el decoder JSON nativo de Wazuh:

    {"integration":"office365","office365":{...campos del evento...}}

UNA LÍNEA = UN EVENTO. Sin prefijos. Las reglas oficiales 9XXXX matchean
contra data.office365.RecordType, data.office365.Operation, etc.

Las reglas custom 108000+ requieren <location>office_365</location>: para
el laboratorio NO las disparamos, atacamos las oficiales 91532, 91545, 91556, etc.
"""
from __future__ import annotations
import json
import random
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass


ORG_ID = "67ef251a-3694-4ccf-8fe2-1aab535b9fc6"
ORG_NAME = "labcorpname.onmicrosoft.com"


def _ts_o365(ts: datetime) -> str:
    """Format Office365 espera: '2026-05-11T23:57:52'."""
    return ts.strftime("%Y-%m-%dT%H:%M:%S")


def _wrap(o365_payload: dict) -> str:
    return json.dumps({"integration": "office365", "office365": o365_payload},
                      separators=(",", ":"))


@dataclass
class UserLoggedIn:
    """STS logon (regla 91545, level 3). Operation=UserLoggedIn."""
    user_id: str = "lab.user2@labcorp.com"
    client_ip: str = "212.64.161.47"
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    result_status: str = "Success"
    risk_state: str = "none"  # 'atRisk' marca login sospechoso
    country: str = "ES"

    def render(self, ts: datetime) -> str:
        ext_props = [
            {"Name": "UserAgent", "Value": self.user_agent},
            {"Name": "RequestType", "Value": "OAuth2:Authorize"},
            {"Name": "ResultStatusDetail", "Value": "Redirect"},
            {"Name": "RiskState", "Value": self.risk_state},
        ]
        payload = {
            "CreationTime": _ts_o365(ts),
            "Id": str(uuid.uuid4()),
            "Operation": "UserLoggedIn",
            "OrganizationId": ORG_ID,
            "RecordType": 15,  # AzureActiveDirectoryStsLogon
            "ResultStatus": self.result_status,
            "UserKey": "10032002" + uuid.uuid4().hex[:10].upper(),
            "UserType": 0,
            "Version": 1,
            "Workload": "AzureActiveDirectory",
            "ClientIP": self.client_ip,
            "ObjectId": self.user_id,
            "UserId": self.user_id,
            "AzureActiveDirectoryEventType": 1,
            "ExtendedProperties": ext_props,
            "ApplicationId": "1950a258-227b-4e31-a9cf-717495945fc2",
            "Country": self.country,
        }
        return _wrap(payload)


@dataclass
class MailItemsAccessed:
    """Acceso a buzón (regla 91578, level 5). Operation=MailItemsAccessed."""
    user_id: str = "lab.user2@labcorp.com"
    client_ip: str = "212.64.161.47"
    client_process: str = "OUTLOOK.EXE"
    access_type: str = "Sync"  # 'Bind' es más sospechoso (acceso por terceros)

    def render(self, ts: datetime) -> str:
        payload = {
            "AppAccessContext": {"APIId": ""},
            "CreationTime": _ts_o365(ts),
            "Id": str(uuid.uuid4()),
            "Operation": "MailItemsAccessed",
            "OrganizationId": ORG_ID,
            "RecordType": 2,  # ExchangeItem
            "ResultStatus": "Succeeded",
            "UserKey": "10032002" + uuid.uuid4().hex[:10].upper(),
            "UserType": 0,
            "Version": 1,
            "Workload": "Exchange",
            "ClientIP": self.client_ip,
            "UserId": self.user_id,
            "ClientIPAddress": self.client_ip,
            "ClientInfoString": "Client=MSExchangeRPC",
            "ClientProcessName": self.client_process,
            "ExternalAccess": False,
            "InternalLogonType": 0,
            "LogonType": 0,
            "MailboxOwnerUPN": self.user_id,
            "OperationProperties": [
                {"Name": "MailAccessType", "Value": self.access_type}
            ],
            "OrganizationName": ORG_NAME,
            "Subscription": "Audit.Exchange",
        }
        return _wrap(payload)


@dataclass
class NewInboxRule:
    """Creación de regla en buzón. Útil como signal de phishing post-acceso.
    Operation='New-InboxRule'."""
    user_id: str = "lab.user2@labcorp.com"
    client_ip: str = "212.64.161.47"
    rule_name: str = "forward-external"
    forward_to: str = "attacker@malicious.tld"

    def render(self, ts: datetime) -> str:
        payload = {
            "CreationTime": _ts_o365(ts),
            "Id": str(uuid.uuid4()),
            "Operation": "New-InboxRule",
            "OrganizationId": ORG_ID,
            "RecordType": 1,  # ExchangeAdmin
            "ResultStatus": "True",
            "UserKey": "10032002" + uuid.uuid4().hex[:10].upper(),
            "UserType": 2,
            "Version": 1,
            "Workload": "Exchange",
            "ClientIP": self.client_ip,
            "UserId": self.user_id,
            "Parameters": [
                {"Name": "Name", "Value": self.rule_name},
                {"Name": "ForwardTo", "Value": self.forward_to},
                {"Name": "StopProcessingRules", "Value": "True"},
            ],
            "OrganizationName": ORG_NAME,
        }
        return _wrap(payload)


@dataclass
class AddMailboxPermission:
    """Concesión de FullAccess en mailbox (regla custom 91725, level 7)."""
    user_id: str = "admin@labcorp.com"
    target_mailbox: str = "ceo@labcorp.com"
    permission: str = "FullAccess"

    def render(self, ts: datetime) -> str:
        payload = {
            "CreationTime": _ts_o365(ts),
            "Id": str(uuid.uuid4()),
            "Operation": "Add-MailboxPermission",
            "OrganizationId": ORG_ID,
            "RecordType": 1,
            "ResultStatus": "True",
            "UserKey": "10032002" + uuid.uuid4().hex[:10].upper(),
            "UserType": 2,
            "Version": 1,
            "Workload": "Exchange",
            "UserId": self.user_id,
            "Parameters": [
                {"Name": "Identity", "Value": self.target_mailbox},
                {"Name": "User", "Value": self.user_id},
                {"Name": "AccessRights", "Value": self.permission},
            ],
            "OrganizationName": ORG_NAME,
        }
        return _wrap(payload)


@dataclass
class PhishingDetected:
    """ATP/Defender phishing alert (RecordType=28 → regla custom 91556, level 6)."""
    recipient: str = "lab.user2@labcorp.com"
    sender: str = "ceo@spoofed.tld"
    subject: str = "URGENT: Wire transfer pending approval"

    def render(self, ts: datetime) -> str:
        payload = {
            "CreationTime": _ts_o365(ts),
            "Id": str(uuid.uuid4()),
            "Operation": "Phish",
            "OrganizationId": ORG_ID,
            "RecordType": 28,  # threat intelligence
            "ResultStatus": "Detected",
            "UserKey": "ThreatIntel",
            "UserType": 4,
            "Version": 1,
            "Workload": "Exchange",
            "P1Sender": self.sender,
            "P2Sender": self.sender,
            "Recipients": [self.recipient],
            "Subject": self.subject,
            "Verdict": "Phish",
            "OrganizationName": ORG_NAME,
        }
        return _wrap(payload)


# Ruido benigno
NOISE_USERS = [f"user{i:03d}@labcorp.com" for i in range(50)]
NOISE_IPS_INT = ["212.64.161.47", "212.64.161.48", "85.49.32.10", "62.83.7.41"]


def noise_login_ok(ts: datetime) -> str:
    return UserLoggedIn(
        user_id=random.choice(NOISE_USERS),
        client_ip=random.choice(NOISE_IPS_INT),
        result_status="Success",
        risk_state="none",
        country="ES",
    ).render(ts)


def noise_mail_access(ts: datetime) -> str:
    return MailItemsAccessed(
        user_id=random.choice(NOISE_USERS),
        client_ip=random.choice(NOISE_IPS_INT),
        access_type="Sync",
    ).render(ts)
