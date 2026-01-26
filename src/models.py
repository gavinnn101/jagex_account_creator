from dataclasses import dataclass


@dataclass(frozen=True)
class Proxy:
    ip: str
    port: str
    username: str | None = None
    password: str | None = None


@dataclass(frozen=True)
class IMAPDetails:
    ip: str
    port: int
    email: str
    password: str
