# Convert proxy strings to a Proxy object to be used in `config.toml`.

from pathlib import Path

from loguru import logger

from jagex_account_creator.models import Proxy

SCRIPT_DIR = Path(__file__).resolve().parent

PROXIES_FILE_PATH = SCRIPT_DIR / "proxies.txt"

# This file's contents will be overwritten every run.
CONVERTED_ACCOUNTS_FILE_PATH = SCRIPT_DIR / "converted_proxies.txt"


def main():
    with open(PROXIES_FILE_PATH) as in_file, open(CONVERTED_ACCOUNTS_FILE_PATH, "w") as out_file:
        for line in in_file:
            parts = line.strip().split(":")
            if len(parts) == 2:
                ip, port = parts
                proxy = Proxy(ip=ip, port=int(port))
            elif len(parts) == 4:
                ip, port, username, password = parts
                proxy = Proxy(ip=ip, port=int(port), username=username, password=password)
            else:
                logger.error(f"Skipping line with an invalid proxy format: {line}")
                continue
            logger.info(f"Transforming proxy: {line} -> {proxy} ")
            out_file.write(
                f'{{ ip = "{proxy.ip}", port = "{proxy.port}", username = "{proxy.username}", password = "{proxy.password}" }},\n'
            )


if __name__ == "__main__":
    main()
