from dataclasses import dataclass


@dataclass(frozen=True)
class Proxy:
    ip: str
    port: str
    username: str | None = None
    password: str | None = None


def parse_proxy(proxy_str: str) -> Proxy:
    parts = proxy_str.split(":")
    if len(parts) == 2:
        return Proxy(ip=parts[0], port=int(parts[1]))
    elif len(parts) == 4:
        return Proxy(ip=parts[0], port=int(parts[1]), username=parts[2], password=parts[3])
    raise ValueError(f"Invalid proxy format: {proxy_str}")
