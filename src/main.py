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

import models
from gproxy import GProxy

SCRIPT_DIR = Path(__file__).resolve().parent
ACCOUNTS_FILE_PATH = SCRIPT_DIR / "accounts.json"


class ElementNotFoundError(Exception):
    """Raised when a required element cannot be found."""

    pass


class AccountCreator:
    _cache_folder_lock = threading.Lock()

    def __init__(
        self,
        user_agent: str,
        element_wait_timeout: int,
        cache_update_threshold: float,
        enable_dev_tools: bool,
        imap_details: models.IMAPDetails,
        account_email: str,
        account_password: str,
        proxy: models.Proxy | None = None,
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
            with self._cache_folder_lock:
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

    def get_browser_ip(self, tab: MixTab) -> str | None:
        """Get the IP address that the browser is using."""
        url = "https://api64.ipify.org/?format=raw"
        if not tab.get(url):
            return None
        return tab.ele("tag:pre").text

    def find_element(
        self, tab: MixTab, identifier: str, required: bool = True
    ) -> ChromiumElement | None:
        """Tries to find an element in the tab."""
        logger.debug(f"Looking for element to click with identifier: {identifier}")

        logger.debug("Waiting for element to be loaded")
        if not tab.wait.eles_loaded(identifier):
            if required:
                raise ElementNotFoundError(
                    f"Couldn't find loaded element with identifier: {identifier}"
                )
            return None

        logger.debug("Getting element")
        element = tab.ele(identifier)
        if not element:
            if required:
                raise ElementNotFoundError(f"Couldn't find element with identifier: {identifier}")
            return None

        logger.debug("Waiting for element to be displayed")
        element.wait.displayed()

        logger.debug("Returning element")
        return element

    def click_element(
        self, tab: MixTab, identifier: str, required: bool = True
    ) -> ChromiumElement | None:
        element = self.find_element(tab, identifier, required=required)
        if not element:
            return None
        logger.debug("Clicking element")
        tab.actions.move_to(element).click()
        return element

    def click_and_type(
        self, tab: MixTab, identifier: str, text: str, required: bool = True
    ) -> ChromiumElement | None:
        """Clicks on an element and then types the text."""
        element = self.find_element(tab, identifier, required=required)
        if not element:
            return None
        logger.debug(f"Clicking element and then typing: {text}")
        tab.actions.move_to(element).click().type(text, interval=0.01)
        return element

    def locate_cf_button(self, tab: MixTab) -> ChromiumElement | None:
        """Finds the CF challenge button in the tab. Credit to CloudflareBypasser."""
        logger.info("Looking for CF checkbox.")

        try:
            for ele in tab.eles("tag:input", timeout=1):
                attrs = ele.attrs
                if not (attrs.get("type") == "hidden" and "turnstile" in attrs.get("name", "")):
                    continue

                logger.info(f"Found turnstile input: {attrs['name']}")

                container = ele.parent()
                shadow = container.shadow_root or container.child().shadow_root
                if not shadow:
                    logger.info("Couldn't access shadow root")
                    continue

                iframe = shadow.ele("tag:iframe")
                if not iframe:
                    logger.info("No iframe in shadow root")
                    continue

                frame = tab.get_frame(iframe)
                if not frame:
                    logger.info("Couldn't get frame context")
                    continue

                body = frame.ele("tag:body")
                if body and body.shadow_root:
                    if checkbox := body.shadow_root.ele("tag:input"):
                        return checkbox
        except Exception as e:
            logger.debug(f"Error traversing CF structure: {e}")

        return None

    def bypass_challenge(self, tab: MixTab) -> bool:
        """Attempts to bypass the CF challenge by clicking the checkbox."""
        max_retries = 5
        sleep_seconds = 2

        for attempt in range(max_retries):
            if "Just a moment" not in tab.title:
                logger.info("Challenge already passed or not present.")
                return True

            button = self.locate_cf_button(tab)
            if button:
                logger.info("Found CF challenge button. Clicking.")
                try:
                    button.click()
                except Exception as e:
                    logger.debug(f"Click failed: {e}")
                    continue
                return tab.wait.title_change("Just a moment", exclude=True, timeout=10)

            logger.info(f"Checkbox not found yet, attempt {attempt + 1}/{max_retries}")
            time.sleep(sleep_seconds)

        logger.error("Max retries reached. Failed to bypass CF challenge.")
        return False

    def _get_verification_code(self, account_email: str) -> str | None:
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
        return None

    def _verify_account_creation(self, tab: MixTab) -> bool:
        """Checks to see if we landed on the registration completed page."""
        return tab.wait.title_change("Registration completed")

    def _update_cache(self, run_cache_path: Path) -> None:
        """Update primary cache if run cache is significantly different."""
        with self._cache_folder_lock:
            if not self.cache_folder.is_dir():
                logger.debug("Primary cache doesn't exist. Copying run cache.")
                shutil.copytree(run_cache_path, self.cache_folder)
                return

            run_size = self.get_dir_size(run_cache_path)
            original_size = self.get_dir_size(self.cache_folder)

            if original_size == 0:
                size_diff_percent = 100.0 if run_size else 0.0
            else:
                size_diff_percent = (run_size - original_size) / original_size * 100

            logger.debug(
                f"Cache sizes - run: {run_size}, original: {original_size}, diff: {size_diff_percent:.1f}%"
            )

            if size_diff_percent >= self.cache_update_threshold:
                logger.debug("Updating primary cache.")
                shutil.rmtree(self.cache_folder)
                shutil.copytree(run_cache_path, self.cache_folder)

    def _cleanup(
        self,
        run_path: Path,
        browser: Chromium,
        gproxy: GProxy,
        update_primary_cache: bool = False,
    ) -> None:
        """Cleanup browser, proxy, and temp files."""
        browser.quit()
        gproxy.stop()

        if update_primary_cache:
            self._update_cache(run_path / "cache")

        shutil.rmtree(run_path, ignore_errors=True)

    def _handle_registration(self, browser: Chromium) -> models.JagexAccount | None:
        """Do the account registration flow."""
        tab = browser.latest_tab
        tab.set.auto_handle_alert()

        tab.run_cdp("Network.enable")
        tab.run_cdp("Network.setBlockedURLs", urls=self.urls_to_block)

        browser_ip = self.get_browser_ip(tab)
        if not browser_ip:
            logger.error("Failed to get browser ip. Exiting.")
            return None
        logger.info(f"Browser IP: {browser_ip}")

        jagex_account = models.JagexAccount(
            email=self.account_email,
            password=self.account_password,
            birthday=models.Birthday(
                day=random.randint(1, 25),
                month=random.randint(1, 12),
                year=random.randint(1979, 2010),
            ),
            real_ip=browser_ip,
            proxy=self.proxy,
        )

        if not tab.get(self.registration_url):
            logger.error(f"Failed to go to url: {self.registration_url}")
            return None

        tab.wait.title_change("Create a Jagex account")
        tab.wait.url_change(self.registration_url)

        if "Sorry, you have been blocked" in tab.html:
            logger.error("IP is blocked by CF. Exiting.")
            return None

        self.click_and_type(tab, "@id:email", jagex_account.email)
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-day",
            str(jagex_account.birthday.day),
        )
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-month",
            str(jagex_account.birthday.month),
        )
        self.click_and_type(
            tab,
            "@id:registration-start-form--field-year",
            str(jagex_account.birthday.year),
        )
        self.click_element(tab, "@id:registration-start-accept-agreements")
        self.click_element(tab, "@id:registration-start-form--continue-button")
        tab.wait.doc_loaded()

        code = self._get_verification_code(self.account_username)
        if not code:
            logger.error("Failed to get registration verification code.")
            return None
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
            logger.error("Failed to verify account creation.")
            return None

        if self.set_2fa:
            logger.debug("Going to management page")
            if not tab.get(self.management_url):
                logger.error("Failed to get to the account management page.")
                return None
            tab.wait.doc_loaded()

            while "Just a moment" not in tab.title:
                time.sleep(0.1)
            self.bypass_challenge(tab)

            tab.wait.url_change(self.management_url)

            self.click_element(tab, "@data-testid:mfa-enable-totp-button")
            self.click_element(tab, "@id:authentication-setup-show-secret")

            setup_key_element = self.find_element(tab, "@id:authentication-setup-secret-key")
            setup_key = setup_key_element.text
            logger.debug(f"Extracted 2fa setup key: {setup_key}")

            self.click_element(tab, "@data-testid:authenticator-setup-qr-button")
            totp = pyotp.TOTP(setup_key).now()
            logger.debug(f"Generated TOTP code: {totp}")

            self.click_and_type(tab, "@id:authentication-setup-verification-code", totp)
            self.click_element(tab, "@data-testid:authentication-setup-qr-code-submit-button")

            backup_codes_element = self.find_element(tab, "@id:authentication-setup-complete-codes")
            backup_codes = backup_codes_element.text.split("\n")
            logger.debug(f"Got 2fa backup codes: {backup_codes}")

            jagex_account.tfa = models.TwoFactorAuth(setup_key=setup_key, backup_codes=backup_codes)

        logger.info("Registration finished")
        return jagex_account

    def register_account(self) -> models.JagexAccount | None:
        """Wrapper function to fully register a Jagex account."""
        run_number = random.randint(10_000, 65_535)
        run_path = SCRIPT_DIR / f"run_{run_number}"
        run_path.mkdir()

        gproxy = GProxy(upstream_proxy=self.proxy, allowed_hosts=["jagex", "cloudflare", "ipify"])
        gproxy.start()

        browser = self.get_new_browser(run_path, gproxy.ip, gproxy.port)

        success = False
        try:
            result = self._handle_registration(browser=browser)
            success = result is not None
            return result
        except ElementNotFoundError as e:
            logger.error(f"Registration failed: {e}")
            return None
        finally:
            self._cleanup(
                run_path=run_path, browser=browser, gproxy=gproxy, update_primary_cache=success
            )


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


def load_accounts(accounts_file_path: Path) -> list[models.JagexAccount]:
    """Loads accounts from file."""
    if accounts_file_path.is_file() and accounts_file_path.stat().st_size > 0:
        with open(accounts_file_path) as f:
            raw = json.load(f)
        return [models.JagexAccount.model_validate(data) for data in raw]
    return []


def save_accounts(accounts_file_path: Path, accounts: list[models.JagexAccount]) -> None:
    """Saves accounts list to file."""
    raw = [account.model_dump() for account in accounts]
    with open(accounts_file_path, "w") as f:
        json.dump(raw, f, indent=4)


def save_account_to_file(accounts_file_path: Path, account: models.JagexAccount) -> None:
    """Saves created account to accounts file."""
    logger.debug(f"Saving account: {account.email} to file: {accounts_file_path}")
    accounts = load_accounts(accounts_file_path=accounts_file_path)
    accounts.append(account)
    save_accounts(accounts_file_path=accounts_file_path, accounts=accounts)


def main():
    with open(SCRIPT_DIR / "config.toml", "rb") as f:
        config = tomllib.load(f)

    logger.remove()
    logger.add(sys.stderr, level=config["default"]["log_level"])

    logger.info("Starting account creator.")

    imap_details = models.IMAPDetails(
        ip=config["imap"]["ip"],
        port=config["imap"]["port"],
        email=config["imap"]["email"],
        password=config["imap"]["password"],
    )

    accounts_to_create = config["default"]["accounts_to_create"]
    domains = config["account"]["domains"]
    account_password = config["account"]["password"]
    set_2fa = config["account"]["set_2fa"]

    use_headless_browser = config["browser"]["headless"]
    enable_dev_tools = config["browser"]["enable_dev_tools"]
    element_wait_timeout = config["browser"]["element_wait_timeout"]
    cache_update_threshold = config["browser"]["cache_update_threshold"]

    proxies_enabled = config["proxies"]["enabled"]
    proxies: list[models.Proxy] = [models.Proxy(**p) for p in config["proxies"]["list"]]

    with ThreadPoolExecutor(max_workers=config["default"]["threads"]) as executor:
        futures: list[Future] = []

        for i in range(accounts_to_create):
            account_username = generate_username()
            account_domain = get_account_domain(domains=domains)
            account_email = f"{account_username}@{account_domain}"

            if proxies_enabled:
                proxy = proxies[i % len(proxies)]
            else:
                proxy = None

            ac = AccountCreator(
                user_agent=config["browser"]["user_agent"],
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
                save_account_to_file(accounts_file_path=ACCOUNTS_FILE_PATH, account=result)
            except Exception as e:
                logger.error(f"Account creation failed: {e}")


if __name__ == "__main__":
    main()
