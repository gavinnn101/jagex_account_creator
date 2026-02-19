import random
import string
import threading
from pathlib import Path

from loguru import logger

import models


def generate_username(length: int = 10) -> str:
    """Generate a unique string based on length provided."""
    characters = string.ascii_letters + string.digits
    username = "".join(random.choice(characters.lower()) for _ in range(length))
    logger.debug(f"Returning generated username: {username} of length: {length}")
    return username


def get_account_domain(domains: list[str]) -> str:
    """Get a random domain to use for the account."""
    index = random.randint(0, len(domains) - 1)
    return domains[index]


def save_account_to_file(
    accounts_file_path: Path, accounts_file_lock: threading.Lock, account: models.JagexAccount
) -> None:
    """Saves created account to accounts file."""
    with accounts_file_lock:
        logger.debug(f"Saving account: {account.email} to file: {accounts_file_path}")
        with open(accounts_file_path, "a") as f:
            f.write(account.model_dump_json() + "\n")
