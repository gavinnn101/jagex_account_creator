import random
import secrets
import string
import threading
from pathlib import Path

from loguru import logger

from . import models


def generate_string(include_punctuation: bool, length: int = 16) -> str:
    """Generate a unique string to use for accounts."""
    characters = string.ascii_letters + string.digits
    if include_punctuation:
        characters += string.punctuation
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
