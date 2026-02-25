import random
import sys
import threading
import time
import tomllib
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any

from loguru import logger

from jagex_account_creator import models, utils
from jagex_account_creator.account_creator import AccountCreator

SCRIPT_DIR = Path(__file__).resolve().parent
CONFIG_PATH = SCRIPT_DIR / "config.toml"

ACCOUNTS_FILE_PATH = SCRIPT_DIR / "accounts.jsonl"
ACCOUNTS_FILE_LOCK = threading.Lock()


def setup_logging(config: dict[str, Any]) -> None:
    """Setup the logger to filter logs based on the different module log_levels in the config."""
    log_levels = {
        "AccountCreator": config["account_creator"]["log_level"],
        "GProxy": config["gproxy"]["log_level"],
    }

    def log_format(record: dict) -> str:
        uid = record["extra"].get("uid", "-")
        return (
            "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
            f"<yellow>[{uid}]</yellow> "
            "<level>{message}</level>\n{exception}"
        )

    logger.remove()

    for module, level in log_levels.items():
        logger.add(
            sys.stderr,
            level=level,
            format=log_format,
            filter=lambda record, name=module: record["extra"].get("module") == name,
        )

    configured_modules = set(log_levels.keys())
    logger.add(
        sys.stderr,
        level="INFO",
        format=log_format,
        filter=lambda record: record["extra"].get("module") not in configured_modules,
    )


def handle_result(
    future: Future,
    email: str,
    counters: dict,
    counter_lock: threading.Lock,
    accounts_to_create: int,
) -> None:
    """Callback function to handle processing a future (account creation) result."""
    try:
        result: models.AccountRegistrationResult = future.result()
    except Exception as e:
        logger.exception(f"Account creation for account: {email} failed: {e}")
        with counter_lock:
            counters["failed"] += 1
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
        with counter_lock:
            counters["created"] += 1
            logger.info(f"Created {counters['created']}/{accounts_to_create} accounts.")


def main():
    with open(CONFIG_PATH, "rb") as f:
        config = tomllib.load(f)

    setup_logging(config=config)

    logger.info("Starting account creator.")

    mail_provider = models.MailProvider(config["email"]["mail_provider"].lower())

    imap_details = None
    if mail_provider == models.MailProvider.IMAP:
        imap_details = models.IMAPDetails(
            ip=config["email"]["imap"]["ip"],
            port=config["email"]["imap"]["port"],
            email=config["email"]["imap"]["email"],
            password=config["email"]["imap"]["password"],
        )
        domains = config["email"]["imap"]["domains"]
    elif mail_provider == models.MailProvider.GUERRILLA_MAIL:
        domains = config["email"]["guerrilla_mail"]["domains"]
    elif mail_provider == models.MailProvider.XITROO:
        domains = ["xitroo.com"]
    else:
        logger.error("Must use `imap`, `guerrilla_mail`, or `xitroo` for `[email] mail_provider`.")
        return

    if config["proxies"]["enabled"]:
        proxies: list[models.Proxy] = [models.Proxy(**p) for p in config["proxies"]["list"]]
        # Start at a random proxy index so we don't abuse the first proxy in the list.
        proxy_start_index = random.randint(0, len(proxies) - 1)

    accounts_to_create = config["account_creator"]["accounts_to_create"]
    logger.info(f"Creating {accounts_to_create} accounts.")

    account_creation_counters = {"created": 0, "failed": 0}
    account_creation_counters_lock = threading.Lock()

    with ThreadPoolExecutor(max_workers=config["account_creator"]["threads"]) as executor:
        for i in range(accounts_to_create):
            account_username = utils.generate_string(
                include_punctuation=False, length=config["account"]["username_length"]
            )
            account_password = config["account"]["password"]
            if not account_password:
                account_password = utils.generate_string(
                    include_punctuation=True, length=config["account"]["random_password_length"]
                )
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
                account_password=account_password,
                mail_provider=mail_provider,
                set_2fa=config["account"]["set_2fa"],
                use_headless_browser=config["browser"]["headless"],
                imap_details=imap_details,
                use_proxy_for_temp_mail=config["email"]["use_proxy_for_temp_mail"],
            )
            future = executor.submit(ac.register_account)
            future.add_done_callback(
                lambda f, e=account_email: handle_result(
                    f,
                    e,
                    account_creation_counters,
                    account_creation_counters_lock,
                    accounts_to_create,
                )
            )
            time.sleep(1)

    logger.info("Finished creating accounts.")
    logger.info(
        f"Total account creation attempts: {account_creation_counters['created'] + account_creation_counters['failed']}"
    )
    logger.info(f"Successful creations: {account_creation_counters['created']}")
    logger.info(f"Failed creations: {account_creation_counters['failed']}")


if __name__ == "__main__":
    main()
