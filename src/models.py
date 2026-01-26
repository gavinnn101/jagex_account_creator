import pyotp
from pydantic import BaseModel, ConfigDict


class Proxy(BaseModel):
    model_config = ConfigDict(frozen=True)

    ip: str
    port: str
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
