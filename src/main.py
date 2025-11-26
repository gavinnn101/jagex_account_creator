import configparser
import json
import os
import random
import re
import shutil
import string
import sys
import threading
import time
from pathlib import Path
from zipfile import ZipFile

import pyotp
import requests
from DrissionPage import Chromium, ChromiumOptions
from DrissionPage.common import Settings
from DrissionPage.items import ChromiumElement, MixTab
from imap_tools import AND, MailBox
from loguru import logger

from proxies.proxy_extension import create_proxy_extension
from traffic_filter_proxy_server import TrafficFilterProxy

SCRIPT_DIR = Path(os.path.dirname(os.path.realpath(__file__)))


class AccountCreator:
    def __init__(self) -> None:
        self.config = configparser.ConfigParser()
        self.config.read(SCRIPT_DIR / "config.ini")
        self.registration_url = (
            "https://account.jagex.com/en-GB/login/registration-start"
        )
        self.management_url = "https://account.jagex.com/en-GB/manage/profile"
        self.accounts_file = SCRIPT_DIR / "accounts.json"
        self.imap_details = {
            "ip": self.config.get("imap", "ip"),
            "port": self.config.getint("imap", "port"),
            "email": self.config.get("imap", "email"),
            "password": self.config.get("imap", "password"),
        }
        self.domains = self.config.get("account", "domains").split(",")
        self.password = self.config.get("account", "password")
        self.set_2fa = self.config.getboolean("account", "set_2fa")

        self.threads = self.config.getint("default", "threads")
        self.headless = self.config.getboolean("default", "headless")
        self.element_wait_timeout = self.config.getint(
            "default", "element_wait_timeout"
        )

        self.use_proxies = self.config.getboolean("proxies", "enabled")
        if self.use_proxies:
            self.proxies = self.load_proxies(SCRIPT_DIR / "proxies" / "proxies.txt")
            self.proxy_index = random.randint(0, len(self.proxies) - 1)
            self.proxies_lock = threading.Lock()

        self.cache_folder = SCRIPT_DIR / "cache"
        self.cache_folder_lock = threading.Lock()
        self.cache_update_threshold = self.config.getfloat(
            "default", "cache_update_threshold"
        )

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

        self.browser_path = SCRIPT_DIR / "brave-v1.84.141-win32-x64"

        Settings.set_language("en")

    def get_dir_size(self, directory: Path) -> int:
        """Return the size of a directory"""
        return sum(f.stat().st_size for f in directory.glob("**/*") if f.is_file())

    def load_proxies(self, proxy_file_path: Path) -> list:
        """Loads a list of proxies from a file."""
        with open(proxy_file_path, "r") as file:
            # Read each line from the file and strip newline characters
            return [line.strip() for line in file.readlines()]

    def get_next_proxy(self) -> str:
        """Gets the next proxy from the list, cycling back to the start if necessary."""
        with self.proxies_lock:
            # Get the proxy at the current index
            proxy = self.proxies[self.proxy_index]
            # Update the index to point to the next proxy
            self.proxy_index = (self.proxy_index + 1) % len(self.proxies)
        return proxy

    def setup_browser_cache(self, co: ChromiumOptions, run_path: Path) -> None:
        """Copies the primary cache and sets copy for current run."""
        run_number = str(run_path).split("_")[-1]
        logger.info(f"Creating cache folder for run number: {run_number}")
        new_cache_folder = run_path / "cache"
        if os.path.isdir(self.cache_folder):
            with self.cache_folder_lock:
                shutil.copytree(self.cache_folder, new_cache_folder)
        co.set_argument(f"--disk-cache-dir={new_cache_folder}")

    def get_browser_binary(self) -> None:
        """Downloads the expected Brave browser binary to use with DrissionPage.
        This is required because Chrome 137 disasbled loading local extensions via cli flag.
        """
        download_url = "https://github.com/brave/brave-browser/releases/download/v1.84.141/brave-v1.84.141-win32-x64.zip"
        download_path = self.browser_path.with_suffix(".zip")

        if self.browser_path.exists():
            return

        try:
            response = requests.get(url=download_url, stream=True)
            response.raise_for_status()

            with open(download_path, "wb") as file:
                for chunk in response.iter_content(chunk_size=8192):
                    file.write(chunk)
        except requests.exceptions.RequestException as e:
            logger.error(f"Error downloading browser zip: {e}")
            sys.exit(1)
        else:
            logger.info("Downloaded browser binary")
            logger.info(
                f"Unzipping download from {download_path} to {self.browser_path}"
            )
            with ZipFile(download_path) as zObject:
                zObject.extractall(path=self.browser_path)
        finally:
            if download_path.exists():
                logger.debug("Deleting browser zip")
                download_path.unlink()

    def get_new_browser(
        self, run_path: Path, proxy_extension_path: Path = None
    ) -> Chromium:
        """Creates a new browser tab with temp settings and an open port."""
        co = ChromiumOptions()
        co.auto_port()
        self.get_browser_binary()
        browser_path = self.browser_path / "brave.exe"
        co.set_paths(browser_path=browser_path)

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

        # custom user-agent is only needed for headless but why not make it consistent.
        co.set_user_agent(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        )

        if self.headless:
            co.set_argument("--headless=new")
        elif self.config.getboolean("default", "enable_dev_tools"):
            co.set_argument("--auto-open-devtools-for-tabs")

        if proxy_extension_path:
            logger.debug(f"Using proxy extension path: {proxy_extension_path}")
            co.add_extension(path=proxy_extension_path)

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

    def find_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement:
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

    def click_element(
        self, tab: MixTab, identifier: str, teardown: bool = True
    ) -> ChromiumElement:
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
            tab.actions.move_to(element).click()
            for char in text:
                time.sleep(random.uniform(0.100, 0.350))
                tab.actions.type(char)
        return element

    def teardown(self, tab: MixTab, exit_status: str) -> None:
        """Closes tab and exits."""
        logger.info(f"Exiting with status: {exit_status}")
        tab.close()
        sys.exit(exit_status)

    def locate_cf_button(self, tab: MixTab) -> ChromiumElement | None:
        """Finds the CF challenge button in the tab. Credit to CloudflareBypasser."""
        checkbox_wait_seconds = 5
        logger.info(
            f"sleeping {checkbox_wait_seconds} seconds before getting CF checkbox"
        )
        time.sleep(checkbox_wait_seconds)
        logger.info("Looking for CF checkbox.")
        eles = tab.eles("tag:input")
        for ele in eles:
            if "name" in ele.attrs.keys() and "type" in ele.attrs.keys():
                if "turnstile" in ele.attrs["name"] and ele.attrs["type"] == "hidden":
                    return (
                        ele.parent()
                        .shadow_root.child()("tag:body")
                        .shadow_root("tag:input")
                    )
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

    def generate_username(self, length: int = 10) -> str:
        """Generates a unique string based on length provided."""
        characters = string.ascii_letters + string.digits
        username = "".join(random.choice(characters.lower()) for _ in range(length))
        logger.debug(f"Returning generated username: {username} of length: {length}")
        return username

    def get_account_domain(self) -> str:
        """Gets a random domain to use for verification."""
        index = random.randint(0, len(self.domains) - 1)
        return self.domains[index]

    def _get_verification_code(self, tab: MixTab, account_email: str) -> str:
        """Gets the verification code from catch all email via imap"""
        email_query = AND(to=account_email, seen=False)
        code_regex = (
            r'data-testid="registration-started-verification-code"[^>]*>([A-Z0-9]+)<'
        )
        with MailBox(self.imap_details["ip"], self.imap_details["port"]).login(
            self.imap_details["email"], self.imap_details["password"]
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

    def _load_accounts(self) -> dict:
        """Loads accounts from file."""
        accounts = {}
        if (
            os.path.isfile(self.accounts_file)
            and os.path.getsize(self.accounts_file) > 0
        ):
            with open(self.accounts_file, "r") as f:
                accounts = json.load(f)
        return accounts

    def _save_accounts(self, accounts: dict) -> None:
        """Saves accounts dictionary to file."""
        with open(self.accounts_file, "w") as f:
            json.dump(accounts, f, indent=4)

    def _save_account_to_file(self, registration_info: dict) -> None:
        """Saves created account to accounts file."""
        logger.info(
            f"Saving registration info: {registration_info} to file: {self.accounts_file}"
        )
        accounts = self._load_accounts()
        accounts[registration_info["email"]] = registration_info
        self._save_accounts(accounts)

    def register_account(self) -> None:
        """Wrapper function to fully register a Jagex account."""
        registration_info = {
            "email": None,
            "password": self.password,
            "birthday": {"day": None, "month": None, "year": None},
            "proxy": {
                "enabled": self.use_proxies,
                "real_ip": None,
                "host": None,
                "port": None,
                "username": None,
                "password": None,
            },
            "2fa": {"enabled": self.set_2fa, "setup_key": None, "backup_codes": None},
        }

        run_number = random.randint(10_000, 65_535)

        # Create tmp dir for this run
        run_path = SCRIPT_DIR / f"run_{run_number}"
        os.mkdir(run_path)

        if self.use_proxies:
            proxy_extension_dir = run_path / "proxy_extension"
            proxy = self.get_next_proxy()
            logger.debug(f"Returning browser with proxy: {proxy}")

            # Parse proxy string
            proxy_parts = proxy.split(":")

            # Validate proxy format
            if len(proxy_parts) not in [2, 4]:
                logger.error(
                    f"Proxy ({proxy}) doesn't split into ip:port or ip:port:user:pass"
                )
                sys.exit("Invalid proxy")

            # Extract proxy details
            proxy_host, proxy_port = proxy_parts[0], proxy_parts[1]

            # Set auth if provided
            if len(proxy_parts) == 4:
                proxy_username, proxy_password = proxy_parts[2], proxy_parts[3]

                # Store in registration info
                registration_info["proxy"].update(
                    {"username": proxy_username, "password": proxy_password}
                )

            # Update registration info with host and port (always needed)
            registration_info["proxy"].update({"host": proxy_host, "port": proxy_port})

            # Start proxy server to intercept requests
            filter_proxy = TrafficFilterProxy(
                allowed_url_patterns=[
                    "jagex",
                    "cloudflare",
                    "ipify",
                ],
                upstream_proxy=registration_info["proxy"],
            )
            filter_proxy.start_daemon()

            # Create proxy extension
            proxy_extension_path = create_proxy_extension(
                proxy_host=filter_proxy.ip,
                proxy_port=filter_proxy.port,
                plugin_path=proxy_extension_dir,
            )

            browser = self.get_new_browser(run_path, proxy_extension_path)
        else:
            browser = self.get_new_browser(run_path)

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

        username = self.generate_username()
        domain = self.get_account_domain()
        registration_info["email"] = f"{username}@{domain}"

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

        code = self._get_verification_code(tab, username)
        if not code:
            self.teardown(tab, "Failed to get registration verification code.")
        self.click_and_type(tab, "@id:registration-verify-form-code-input", code)
        self.click_element(tab, "@id:registration-verify-form-continue-button")
        tab.wait.doc_loaded()

        self.click_and_type(tab, "@id:displayName", username)
        self.click_element(tab, "@id:registration-account-name-form--continue-button")
        tab.wait.doc_loaded()

        self.click_and_type(tab, "@id:password", self.password)
        self.click_and_type(tab, "@id:repassword", self.password)
        self.click_element(tab, "@id:registration-password-form--create-account-button")
        tab.wait.doc_loaded()

        if not self._verify_account_creation(tab):
            self.teardown(tab, "Failed to verify account creation.")

        if self.set_2fa:
            time.sleep(random.randint(3, 10))
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

            # Extract setup key after clicking the button to show it
            setup_key_element = self.find_element(
                tab, "@id:authentication-setup-secret-key"
            )
            registration_info["2fa"]["setup_key"] = setup_key_element.text
            logger.debug(
                f"Extracted 2fa setup key: {registration_info['2fa']['setup_key']}"
            )

            self.click_element(tab, "@data-testid:authenticator-setup-qr-button")

            # generate totp using the setup key here
            totp = pyotp.TOTP(registration_info["2fa"]["setup_key"]).now()
            logger.debug(f"Generated TOTP code: {totp}")

            self.click_and_type(tab, "@id:authentication-setup-verification-code", totp)
            self.click_element(
                tab, "@data-testid:authentication-setup-qr-code-submit-button"
            )

            backup_codes_element = self.find_element(
                tab, "@id:authentication-setup-complete-codes"
            )
            registration_info["2fa"]["backup_codes"] = backup_codes_element.text.split(
                "\n"
            )
            logger.debug(
                f"Got 2fa backup codes: {registration_info['2fa']['backup_codes']}"
            )

        self._save_account_to_file(registration_info)

        # Close browser before deleting run folder
        browser.close_tabs(tab)

        run_cache_path = run_path / "cache"
        if os.path.isdir(self.cache_folder):
            run_cache_size = self.get_dir_size(run_cache_path)
            original_cache_size = self.get_dir_size(self.cache_folder)
            if original_cache_size == 0:
                if run_cache_size == 0:
                    size_diff_percent = 0  # Both are zero, so no difference
                else:
                    size_diff_percent = 100  # New cache exists but original was empty
            else:
                size_diff_percent = (
                    abs(run_cache_size - original_cache_size)
                    / original_cache_size
                    * 100
                )
            logger.debug(f"run cache size: {run_cache_size}")
            logger.debug(f"original cache size: {original_cache_size}")
            logger.debug(f"Size difference %: {size_diff_percent}")
            if size_diff_percent >= self.cache_update_threshold:
                with self.cache_folder_lock:
                    logger.debug(
                        f"Updating cache file with run cache: {run_cache_path}"
                    )
                    shutil.rmtree(self.cache_folder)
                    shutil.copytree(run_cache_path, self.cache_folder)
        else:
            logger.debug("primary cache doesn't exist. Copying run cache to primary.")
            shutil.copytree(run_cache_path, self.cache_folder)

        logger.debug(f"Deleting run temp folder: {run_path}")
        shutil.rmtree(run_path)

        if self.use_proxies:
            logger.debug("Stopping traffic filter proxy server.")
            filter_proxy.stop()

        logger.info("Registration finished")


def main():
    ac = AccountCreator()

    for _ in range(0, ac.threads):
        threading.Thread(target=ac.register_account).start()
        time.sleep(1)


if __name__ == "__main__":
    main()
