# Convert JagexAccount objects to different formats for account management on different platforms.

from pathlib import Path

from jagex_account_creator.models import JagexAccount

SCRIPT_DIR = Path(__file__).resolve().parent

ACCOUNTS_FILE_PATH = SCRIPT_DIR.parent.parent / "accounts.jsonl"

# This file's contents will be overwritten every run.
CONVERTED_ACCOUNTS_FILE_PATH = SCRIPT_DIR / "converted_accounts.txt"


def main():
    with open(ACCOUNTS_FILE_PATH) as in_file, open(CONVERTED_ACCOUNTS_FILE_PATH, "w") as out_file:
        for line in in_file:
            account = JagexAccount.model_validate_json(line.strip())
            acc_data = f"{account.email.address}:{account.password}"
            if account.tfa:
                acc_data += f":{account.tfa.setup_key}"
            out_file.write(f"{acc_data}\n")


if __name__ == "__main__":
    main()
