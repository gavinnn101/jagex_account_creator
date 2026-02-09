import random
import string
import sys
import threading
import time
import tomllib
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from loguru import logger

import models
from account_creator import AccountCreator

SCRIPT_DIR = Path(__file__).resolve().parent
ACCOUNTS_FILE_PATH = SCRIPT_DIR / "accounts.jsonl"
ACCOUNTS_FILE_LOCK = threading.Lock()


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


def save_account_to_file(accounts_file_path: Path, account: models.JagexAccount) -> None:
    """Saves created account to accounts file."""
    with ACCOUNTS_FILE_LOCK:
        logger.debug(f"Saving account: {account.email} to file: {accounts_file_path}")
        with open(ACCOUNTS_FILE_PATH, "a") as f:
            f.write(account.model_dump_json() + "\n")


def setup_logging(config: dict[str, Any]) -> None:
    """Setup the logger to filter logs based on the different module log_levels in the config."""
    log_levels = {
        "AccountCreator": config["account_creator"]["log_level"],
        "GProxy": config["gproxy"]["log_level"],
    }
    logger.remove()

    for module, level in log_levels.items():
        logger.add(
            sys.stderr,
            level=level,
            filter=lambda record, name=module: record["extra"].get("module") == name,
        )

    configured_modules = set(log_levels.keys())
    logger.add(
        sys.stderr,
        level="INFO",
        filter=lambda record: record["extra"].get("module") not in configured_modules,
    )


def main():
    with open(SCRIPT_DIR / "config.toml", "rb") as f:
        config = tomllib.load(f)

    setup_logging(config=config)

    logger.info("Starting account creator.")

    use_guerrilla_mail = config["email"]["use_guerrilla_mail"]
    use_imap = config["email"]["use_imap"]
    imap_details = None
    if use_imap and use_guerrilla_mail:
        logger.error("`use_imap` and `use_guerrilla_mail` can't both be True.")
        return
    elif use_imap:
        imap_details = models.IMAPDetails(
            ip=config["email"]["imap"]["ip"],
            port=config["email"]["imap"]["port"],
            email=config["email"]["imap"]["email"],
            password=config["email"]["imap"]["password"],
        )
        domains = config["email"]["imap"]["domains"]
    elif use_guerrilla_mail:
        domains = config["email"]["guerrilla_mail"]["domains"]
    else:
        logger.error("Must use either imap or guerrilla mail.")
        return

    proxies: list[models.Proxy] = [models.Proxy(**p) for p in config["proxies"]["list"]]

    with ThreadPoolExecutor(max_workers=config["account_creator"]["threads"]) as executor:
        future_to_email: dict[Future, str] = {}

        for i in range(config["account_creator"]["accounts_to_create"]):
            account_username = generate_username()
            account_domain = get_account_domain(domains=domains)
            account_email = f"{account_username}@{account_domain}"

            if config["proxies"]["enabled"]:
                proxy = proxies[i % len(proxies)]
            else:
                proxy = None

            ac = AccountCreator(
                user_agent=config["browser"]["user_agent"],
                element_wait_timeout=config["browser"]["element_wait_timeout"],
                cache_update_threshold=config["browser"]["cache_update_threshold"],
                enable_dev_tools=config["browser"]["enable_dev_tools"],
                proxy=proxy,
                account_email=account_email,
                account_password=config["account"]["password"],
                set_2fa=config["account"]["set_2fa"],
                use_headless_browser=config["browser"]["headless"],
                imap_details=imap_details,
                use_proxy_for_guerrilla_mail=config["email"]["guerrilla_mail"]["use_proxy"],
            )
            future = executor.submit(ac.register_account)
            future_to_email[future] = account_email

            time.sleep(1)

        for future in as_completed(future_to_email):
            email = future_to_email[future]
            try:
                result = future.result()
            except Exception as e:
                logger.error(f"Account creation for account: {email} failed: {e}")
            else:
                logger.success(f"Account created: {result}")
                save_account_to_file(accounts_file_path=ACCOUNTS_FILE_PATH, account=result)


if __name__ == "__main__":
    main()
