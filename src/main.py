import json
import random
import re
import shutil
import string
import sys
import threading
import time
import tomllib
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path

import pyotp
from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.common import Settings
from DrissionPage.items import ChromiumElement, MixTab
from imap_tools import AND, MailBox
from loguru import logger

from models import IMAPDetails, Proxy
from traffic_filter_proxy_server import TrafficFilterProxy

SCRIPT_DIR = Path(__file__).resolve().parent

LOG_LEVEL = "INFO"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
ACCOUNTS_FILE_PATH = SCRIPT_DIR / "accounts.json"


class AccountCreator:
    def __init__(
        self,
        user_agent: str,
        element_wait_timeout: int,
        cache_update_threshold: float,
        enable_dev_tools: bool,
        imap_details: IMAPDetails,
        account_email: str,
        account_password: str,
        proxy: Proxy | None = None,
        set_2fa: bool = False,
        use_headless_browser: bool = False,
    ) -> None:
        self.user_agent = user_agent
        self.enable_dev_tools = enable_dev_tools

        self.proxy = proxy
        self.imap_details = imap_details
        self.account_email = account_email
        self.account_username = account_email.split("@")[0]
        self.account_password = account_password
        self.set_2fa = set_2fa
        self.use_headless_browser = use_headless_browser

        self.registration_url = "https://account.jagex.com/en-GB/login/registration-start"
        self.management_url = "https://account.jagex.com/en-GB/manage/profile"

        self.element_wait_timeout = element_wait_timeout

        self.cache_update_threshold = cache_update_threshold
        self.cache_folder = SCRIPT_DIR / "cache"
        self.cache_folder_lock = threading.Lock()

        self.urls_to_block = [
            ".ico",
            # ".jpg",
            # ".png",
            ".gif",
            ".svg",
            ".webp",
            "data:image",
            ".woff",
            ".woff2",
            ".woff2!static",
            ".ttf",
            ".otf",
            ".eot",
            "analytics",
            "tracking",
            "google-analytics",
            ".googleapis.",
            "chargebee",
            "cookiebot",
            "beacon",
        ]

        Settings.set_language("en")

    def get_dir_size(self, directory: Path) -> int:
        """Return the size of a directory"""
        return sum(f.stat().st_size for f in directory.glob("**/*") if f.is_file())

    def setup_browser_cache(self, co: ChromiumOptions, run_path: Path) -> None:
        """Copies the primary cache and sets copy for current run."""
        run_number = str(run_path).split("_")[-1]
        logger.info(f"Creating cache folder for run number: {run_number}")
        new_cache_folder = run_path / "cache"
        if self.cache_folder.is_dir():
            with self.cache_folder_lock:
                shutil.copytree(self.cache_folder, new_cache_folder)
        co.set_argument(f"--disk-cache-dir={new_cache_folder}")

    def get_new_browser(self, run_path: Path, ip: str, port: int) -> Chromium:
        """Creates a new browser tab with temp settings and an open port."""
        co = ChromiumOptions()
        co.auto_port()

        co.mute()
        # co.no_imgs()  # no_imgs() seems to cause cloudflare challenge to infinite loop

        # Disable chrome optimization features to save on bandwidth
        # https://source.chromium.org/chromium/chromium/src/+/main:components/optimization_guide/core/optimization_guide_features.cc;l=49-71
        # TODO: Investigate why this doesn't work. Not sure if its DrissionPage not setting them correctly or a different issue.
        # co.set_argument(
        #     "--disable-features=OptimizationGuideModelDownloading,OptimizationHints,OptimizationHintsFetching,OptimizationHintsFetchingAnonymousDataConsent,OptimizationTargetPrediction"
        # )

        self.setup_browser_cache(co, run_path=run_path)

        co.set_timeouts(self.element_wait_timeout)

        if self.user_agent:
            co.set_user_agent(self.user_agent)

        if self.use_headless_browser:
            co.set_argument("--headless=new")
            if not self.user_agent:
                logger.warning(
                    "Using headless without setting a user agent. This will likely get your session detected."
                )
        elif self.enable_dev_tools:
            co.set_argument("--auto-open-devtools-for-tabs")

        co.set_proxy(f"http://{ip}:{port}")

        browser = Chromium(addr_or_opts=co)
        return browser

    def get_browser_ip(self, tab: MixTab) -> str:
        """Get the IP address that the browser is using."""
        url = "https://api64.ipify.org/?format=raw"
        if tab.get(url):
            ip = tab.ele("tag:pre").text
            return ip
        else:
            self.teardown(tab, "Couldn't get browser ip!")

    def find_element(self, tab: MixTab, identifier: str, teardown: bool = True) -> ChromiumElement:
        """Tries to find an element in the tab."""
        logger.debug(f"Looking for element to click with identifier: {identifier}")

        logger.debug("Waiting for element to be loaded")
        found_element = tab.wait.eles_loaded(identifier)
        if not found_element:
            error_msg = f"Couldn't find loaded element with identifier: {identifier}"
            if teardown:
                self.teardown(tab, error_msg)
            else:
                logger.warning(error_msg)
                return

        logger.debug("Getting element")
        element = tab.ele(identifier)
        logger.debug("Waiting for element to be displayed")
        element.wait.displayed()
        if not element:
            error_msg = f"Couldn't find element with identifier: {identifier}"
            if teardown:
                self.teardown(tab, error_msg)
            else:
                logger.warning(error_msg)

        logger.debug("Returning element")
        return element

    def click_element(self, tab: MixTab, identifier: str, teardown: bool = True) -> ChromiumElement:
        element = self.find_element(tab, identifier, teardown)
        if element:
            logger.debug("Clicking element")
            tab.actions.move_to(element).click()
        return element

    def click_and_type(
        self, tab: MixTab, identifier: str, text: str, teardown: bool = True
    ) -> ChromiumElement:
        """Clicks on an element and then types the text."""
        element = self.find_element(tab, identifier, teardown)
        if element:
            logger.debug(f"Clicking element and then typing: {text}")
            key_press_interval = 0.01
            tab.actions.move_to(element).click().type(text, interval=key_press_interval)
        return element

    def teardown(self, tab: MixTab, exit_status: str) -> None:
        """Closes tab and exits."""
        logger.info(f"Exiting with status: {exit_status}")
        tab.close()
        sys.exit(exit_status)

    def locate_cf_button(self, tab: MixTab) -> ChromiumElement | None:
        """Finds the CF challenge button in the tab. Credit to CloudflareBypasser."""
        checkbox_wait_seconds = 5
        logger.info(f"sleeping {checkbox_wait_seconds} seconds before getting CF checkbox")
        time.sleep(checkbox_wait_seconds)
        logger.info("Looking for CF checkbox.")
        eles = tab.eles("tag:input")
        for ele in eles:
            if "name" in ele.attrs.keys() and "type" in ele.attrs.keys():
                if "turnstile" in ele.attrs["name"] and ele.attrs["type"] == "hidden":
                    return ele.parent().shadow_root.child()("tag:body").shadow_root("tag:input")
        return None

    def bypass_challenge(self, tab: MixTab) -> bool:
        """Attempts to bypass the CF challenge by clicking the checkbox."""
        sleep_seconds = 2
        max_retries = 2
        retry_count = 0

        # Poll for the CF challenge button, with a maximum retry count
        while retry_count < max_retries:
            button = self.locate_cf_button(tab)
            if button:
                logger.debug("Found CF challenge button. Clicking.")
                tab.actions.move_to(button).click()
                return tab.wait.title_change("Just a moment", exclude=True)

            logger.warning(
                f"Couldn't find CF challenge button. Retrying in {sleep_seconds} seconds."
            )
            time.sleep(sleep_seconds)
            retry_count += 1

        logger.error("Max retries reached. Failed to find CF challenge button.")
        return False

    def _get_verification_code(self, tab: MixTab, account_email: str) -> str:
        """Gets the verification code from catch all email via imap"""
        email_query = AND(to=account_email, seen=False)
        code_regex = r'data-testid="registration-started-verification-code"[^>]*>([A-Z0-9]+)<'
        with MailBox(self.imap_details.ip, self.imap_details.port).login(
            self.imap_details.email, self.imap_details.password
        ) as mailbox:
            for _ in range(self.element_wait_timeout * 10):
                emails = mailbox.fetch(email_query)
                for email in emails:
                    match = re.search(code_regex, email.html)
                    if match:
                        return match.group(1)
                time.sleep(0.1)
        self.teardown(tab, "Verification code pattern not found in email")

    def _verify_account_creation(self, tab: MixTab) -> bool:
        """Checks to see if we landed on the registration completed page."""
        return tab.wait.title_change("Registration completed")

    def register_account(self) -> None:
        """Wrapper function to fully register a Jagex account."""
        registration_info = {
            "email": None,
            "password": self.account_password,
            "birthday": {"day": None, "month": None, "year": None},
            "proxy": {
                "enabled": False,
                "real_ip": None,
                "host": None,
                "port": None,
                "username": None,
                "password": None,
            },
            "2fa": {"enabled": self.set_2fa, "setup_key": None, "backup_codes": None},
        }

        run_number = random.randint(10_000, 65_535)

        run_path = SCRIPT_DIR / f"run_{run_number}"
        run_path.mkdir()

        if self.proxy:
            registration_info["proxy"]["enabled"] = True
            registration_info["proxy"]["host"] = self.proxy.ip
            registration_info["proxy"]["port"] = self.proxy.port
            registration_info["proxy"]["username"] = self.proxy.username
            registration_info["proxy"]["password"] = self.proxy.password

        filter_proxy = TrafficFilterProxy(
            allowed_url_patterns=[
                "jagex",
                "cloudflare",
                "ipify",
            ],
            upstream_proxy=self.proxy,
        )
        filter_proxy.start_daemon()

        browser = self.get_new_browser(run_path, filter_proxy.ip, filter_proxy.port)
        tab = browser.latest_tab
        tab.set.auto_handle_alert()

        # tab.set.blocked_urls = self.urls_to_block
        tab.run_cdp("Network.enable")
        tab.run_cdp("Network.setBlockedURLs", urls=self.urls_to_block)

        browser_ip = self.get_browser_ip(tab)
        logger.info(f"Browser IP: {browser_ip}")
        registration_info["proxy"]["real_ip"] = browser_ip

        if not tab.get(self.registration_url):
            self.teardown(f"Failed to go to url: {self.registration_url}")
        tab.wait.title_change("Create a Jagex account")
        tab.wait.url_change(self.registration_url)

        if "Sorry, you have been blocked" in tab.html:
            self.teardown(tab, "IP is blocked by CF. Exiting.")

        # self.click_element(tab, "#CybotCookiebotDialogBodyButtonDecline", False)

        registration_info["email"] = self.account_email

        registration_info["birthday"]["day"] = random.randint(1, 25)
        registration_info["birthday"]["month"] = random.randint(1, 12)
        registration_info["birthday"]["year"] = random.randint(1979, 2010)

        self.click_and_type(tab, "@id:email", registration_info["email"])
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-day",
            str(registration_info["birthday"]["day"]),
        )
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-month",
            str(registration_info["birthday"]["month"]),
        )
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-year",
            str(registration_info["birthday"]["year"]),
        )
        self.click_element(tab, "@id:registration-start-accept-agreements")
        self.click_element(tab, "@id:registration-start-form--continue-button")
        tab.wait.doc_loaded()

        code = self._get_verification_code(tab, self.account_username)
        if not code:
            self.teardown(tab, "Failed to get registration verification code.")
        self.click_and_type(tab, "@id:registration-verify-form-code-input", code)
        self.click_element(tab, "@id:registration-verify-form-continue-button")
        tab.wait.doc_loaded()

        self.click_and_type(tab, "@id:displayName", self.account_username)
        self.click_element(tab, "@id:registration-account-name-form--continue-button")
        tab.wait.doc_loaded()

        self.click_and_type(tab, "@id:password", self.account_password)
        self.click_and_type(tab, "@id:repassword", self.account_password)
        self.click_element(tab, "@id:registration-password-form--create-account-button")
        tab.wait.doc_loaded()

        if not self._verify_account_creation(tab):
            self.teardown(tab, "Failed to verify account creation.")

        if self.set_2fa:
            logger.debug("Going to management page")
            if not tab.get(self.management_url):
                self.teardown(tab, "Failed to get to the account management page.")
            tab.wait.doc_loaded()

            # DrissionPage used to automatically pass this cloudflare check but not atm.
            # For now, we'll always check for a challenge here and solve if needed.
            # self.bypass_challenge(tab)

            tab.wait.url_change(self.management_url)

            self.click_element(tab, "@data-testid:mfa-enable-totp-button")
            self.click_element(tab, "@id:authentication-setup-show-secret")

            setup_key_element = self.find_element(tab, "@id:authentication-setup-secret-key")
            registration_info["2fa"]["setup_key"] = setup_key_element.text
            logger.debug(f"Extracted 2fa setup key: {registration_info['2fa']['setup_key']}")

            self.click_element(tab, "@data-testid:authenticator-setup-qr-button")

            totp = pyotp.TOTP(registration_info["2fa"]["setup_key"]).now()
            logger.debug(f"Generated TOTP code: {totp}")

            self.click_and_type(tab, "@id:authentication-setup-verification-code", totp)
            self.click_element(tab, "@data-testid:authentication-setup-qr-code-submit-button")

            backup_codes_element = self.find_element(tab, "@id:authentication-setup-complete-codes")
            registration_info["2fa"]["backup_codes"] = backup_codes_element.text.split("\n")
            logger.debug(f"Got 2fa backup codes: {registration_info['2fa']['backup_codes']}")

        # Close browser before deleting run folder
        browser.close_tabs(tab)

        run_cache_path = run_path / "cache"

        if not self.cache_folder.is_dir():
            logger.debug("Primary cache doesn't exist. Copying run cache to primary.")
            shutil.copytree(run_cache_path, self.cache_folder)

        run_cache_size = self.get_dir_size(run_cache_path)
        original_cache_size = self.get_dir_size(self.cache_folder)

        if original_cache_size == 0:
            size_diff_percent = 100 if run_cache_size else 0
        else:
            size_diff_percent = (
                abs(run_cache_size - original_cache_size) / original_cache_size * 100
            )

        logger.debug(f"Run cache size: {run_cache_size}")
        logger.debug(f"Original cache size: {original_cache_size}")
        logger.debug(f"Size difference %: {size_diff_percent}")

        if size_diff_percent >= self.cache_update_threshold:
            with self.cache_folder_lock:
                logger.debug(f"Updating cache file with run cache: {run_cache_path}")
                shutil.rmtree(self.cache_folder)
                shutil.copytree(run_cache_path, self.cache_folder)

        logger.debug(f"Deleting run temp folder: {run_path}")
        shutil.rmtree(run_path)

        logger.debug("Stopping traffic filter proxy server.")
        filter_proxy.stop()

        logger.info("Registration finished")
        return registration_info


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


def load_accounts(accounts_file_path: Path) -> dict:
    """Loads accounts from file."""
    accounts = {}
    if accounts_file_path.is_file() and accounts_file_path.stat().st_size > 0:
        with open(accounts_file_path) as f:
            accounts = json.load(f)
    return accounts


def save_accounts(accounts_file_path: Path, accounts: dict) -> None:
    """Saves accounts dictionary to file."""
    with open(accounts_file_path, "w") as f:
        json.dump(accounts, f, indent=4)


def save_account_to_file(accounts_file_path: Path, registration_info: dict) -> None:
    """Saves created account to accounts file."""
    logger.debug(f"Saving registration info: {registration_info} to file: {accounts_file_path}")
    accounts = load_accounts(accounts_file_path=accounts_file_path)
    accounts[registration_info["email"]] = registration_info
    save_accounts(accounts_file_path=accounts_file_path, accounts=accounts)


def main():
    logger.remove()
    logger.add(sys.stderr, level=LOG_LEVEL)

    logger.info("Starting account creator.")

    with open(SCRIPT_DIR / "config.toml", "rb") as f:
        config = tomllib.load(f)

    imap_details = IMAPDetails(
        ip=config["imap"]["ip"],
        port=config["imap"]["port"],
        email=config["imap"]["email"],
        password=config["imap"]["password"],
    )

    accounts_to_create = config["default"]["accounts_to_create"]
    domains = config["account"]["domains"]
    account_password = config["account"]["password"]
    set_2fa = config["account"]["set_2fa"]

    use_headless_browser = config["default"]["headless"]
    enable_dev_tools = config["default"]["enable_dev_tools"]
    element_wait_timeout = config["default"]["element_wait_timeout"]
    cache_update_threshold = config["default"]["cache_update_threshold"]

    proxies: list[Proxy] = [Proxy(**p) for p in config["proxies"]["list"]]

    with ThreadPoolExecutor(max_workers=config["default"]["threads"]) as executor:
        futures: list[Future] = []

        for i in range(accounts_to_create):
            account_username = generate_username()
            account_domain = get_account_domain(domains=domains)
            account_email = f"{account_username}@{account_domain}"

            proxy = proxies[i % len(proxies)]

            ac = AccountCreator(
                user_agent=USER_AGENT,
                element_wait_timeout=element_wait_timeout,
                cache_update_threshold=cache_update_threshold,
                enable_dev_tools=enable_dev_tools,
                proxy=proxy,
                imap_details=imap_details,
                account_email=account_email,
                account_password=account_password,
                set_2fa=set_2fa,
                use_headless_browser=use_headless_browser,
            )
            futures.append(executor.submit(ac.register_account))

        for future in as_completed(futures):
            try:
                result = future.result()
                if not result:
                    logger.error("Failed to create account.")
                    continue

                logger.success(f"Account created: {result}")
                save_account_to_file(
                    accounts_file_path=ACCOUNTS_FILE_PATH, registration_info=result
                )
            except Exception as e:
                logger.error(f"Account creation failed: {e}")


if __name__ == "__main__":
    main()
