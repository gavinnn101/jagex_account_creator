import random
import re
import secrets
import string
import threading
from datetime import timedelta
from pathlib import Path

import rnet
from loguru import logger
from rnet.blocking import Client

from . import models


def generate_string(
    include_punctuation: bool,
    excluded_characters: frozenset = frozenset(),
    length: int = 16,
) -> str:
    """Generate a unique string.

    Args:
        include_punctuation: Include punctuation characters.
        excluded_characters: Characters to exclude from the pool used for the string.
        length: Length of the generated string.

    Raises:
        ValueError: If exclusions deplete a required character category.
    """
    characters = string.ascii_letters + string.digits
    if include_punctuation:
        characters += string.punctuation
    if excluded_characters:
        characters = "".join(c for c in characters if c not in excluded_characters)

    required = [string.ascii_uppercase, string.ascii_lowercase, string.digits]
    if include_punctuation:
        required.append(string.punctuation)
    for category in required:
        if not any(c in characters for c in category):
            raise ValueError(f"All characters excluded from a required category: {category!r}")

    while True:
        password = "".join(secrets.choice(characters) for _ in range(length))
        if (
            any(c.isupper() for c in password)
            and any(c.islower() for c in password)
            and any(c.isdigit() for c in password)
            and (not include_punctuation or any(c in string.punctuation for c in password))
        ):
            return password


def get_account_domain(domains: list[str]) -> str:
    """Get a random domain to use for the account."""
    index = random.randint(0, len(domains) - 1)
    return domains[index]


def save_account_to_file(
    accounts_file_path: Path, accounts_file_lock: threading.Lock, account: models.JagexAccount
) -> None:
    """Saves created account to accounts file."""
    with accounts_file_lock:
        if not accounts_file_path.parent.exists():
            accounts_file_path.parent.mkdir(parents=True)
        logger.debug(f"Saving account: {account.email} to file: {accounts_file_path}")
        with open(accounts_file_path, "a") as f:
            f.write(account.model_dump_json() + "\n")
        logger.debug(f"Account: {account.email} saved to file: {accounts_file_path}")


_CHROME_EMULATION_MAP: dict[int, rnet.Emulation] = {}
for name in dir(rnet.Emulation):
    m = re.search(r"(\d+)", name)
    if m:
        _CHROME_EMULATION_MAP[int(m.group(1))] = getattr(rnet.Emulation, name)


def setup_rnet_client(user_agent: str, timeout_seconds: int) -> Client:
    """Setup an rnet client."""
    if "Windows" in user_agent:
        emulation_os = rnet.EmulationOS.Windows
    elif "Macintosh" in user_agent:
        emulation_os = rnet.EmulationOS.MacOS
    elif "Linux" in user_agent:
        emulation_os = rnet.EmulationOS.Linux
    else:
        emulation_os = rnet.EmulationOS.Windows

    match = re.search(r"Chrome/(\d+)", user_agent)
    chrome_version = int(match.group(1)) if match else max(_CHROME_EMULATION_MAP)
    closest = min(_CHROME_EMULATION_MAP, key=lambda v: abs(v - chrome_version))

    return Client(
        emulation=rnet.EmulationOption(
            emulation=_CHROME_EMULATION_MAP[closest],
            emulation_os=emulation_os,
        ),
        user_agent=user_agent,
        timeout=timedelta(seconds=timeout_seconds),
    )
