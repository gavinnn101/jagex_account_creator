from dataclasses import dataclass

import pyotp
from pydantic import BaseModel, ConfigDict


class Proxy(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip: str
    port: int
    username: str | None = None
    password: str | None = None


class IMAPDetails(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip: str
    port: int
    email: str
    password: str


class Birthday(BaseModel):
    model_config = ConfigDict(frozen=True)

    day: int
    month: int
    year: int


class TwoFactorAuth(BaseModel):
    model_config = ConfigDict(frozen=True)

    setup_key: str
    backup_codes: list[str]

    def get_totp_code(self) -> str:
        return pyotp.TOTP(self.setup_key).now()


class JagexAccount(BaseModel):
    email: str
    password: str
    birthday: Birthday
    real_ip: str
    proxy: Proxy | None = None
    tfa: TwoFactorAuth | None = None


@dataclass(slots=True)
class TransferStats:
    bytes_sent: int = 0
    bytes_received: int = 0

    def __iadd__(self, other: "TransferStats") -> "TransferStats":
        self.bytes_sent += other.bytes_sent
        self.bytes_received += other.bytes_received
        return self


@dataclass(frozen=True)
class AccountRegistrationResult:
    jagex_account: JagexAccount
    transfer_stats: TransferStats
