import random
import sys
import threading
import time
import tomllib
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from loguru import logger

import models
import utils
from account_creator import AccountCreator

SCRIPT_DIR = Path(__file__).resolve().parent
ACCOUNTS_FILE_PATH = SCRIPT_DIR / "accounts.jsonl"
ACCOUNTS_FILE_LOCK = threading.Lock()


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

    if config["proxies"]["enabled"]:
        proxies: list[models.Proxy] = [models.Proxy(**p) for p in config["proxies"]["list"]]
        proxy_start_index = random.randint(0, len(proxies) - 1)

    accounts_to_create = config["account_creator"]["accounts_to_create"]
    accounts_created = 0
    account_creations_failed = 0
    logger.info(f"Creating {accounts_to_create} accounts.")

    with ThreadPoolExecutor(max_workers=config["account_creator"]["threads"]) as executor:
        future_to_email: dict[Future, str] = {}

        for i in range(accounts_to_create):
            account_username = utils.generate_username()
            account_domain = utils.get_account_domain(domains=domains)
            account_email = f"{account_username}@{account_domain}"

            if config["proxies"]["enabled"] and proxies:
                proxy = proxies[(proxy_start_index + i) % len(proxies)]
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
                result: models.AccountRegistrationResult = future.result()
            except Exception as e:
                logger.exception(f"Account creation for account: {email} failed: {e}")
                account_creations_failed += 1
            else:
                total_data_used_mb = (
                    result.transfer_stats.bytes_sent + result.transfer_stats.bytes_received
                ) / 1_048_576
                logger.success(
                    f"Account created: {result.jagex_account}. Total data used: {total_data_used_mb:.2f}MB. Time taken: {result.duration}"
                )
                utils.save_account_to_file(
                    accounts_file_path=ACCOUNTS_FILE_PATH,
                    accounts_file_lock=ACCOUNTS_FILE_LOCK,
                    account=result.jagex_account,
                )
                accounts_created += 1
                logger.info(f"Created {accounts_created}/{accounts_to_create} accounts.")

        logger.info("Finished creating accounts.")
        logger.info(
            f"Total account creation attempts: {accounts_created + account_creations_failed}"
        )
        logger.info(f"Successful creations: {accounts_created}")
        logger.info(f"Failed creations: {account_creations_failed}")


if __name__ == "__main__":
    main()
