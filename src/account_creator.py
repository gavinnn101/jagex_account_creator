import random
import re
import shutil
import threading
import time
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


class ElementNotFoundError(Exception):
    """Raised when a required element cannot be found."""

    pass


class RegistrationError(Exception):
    """An error that occurred during account registration."""

    pass


class AccountCreator:
    _CACHE_FOLDER_LOCK = threading.Lock()

    _URLS_TO_BLOCK = [
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

    _REGISTRATION_URL = "https://account.jagex.com/en-GB/login/registration-start"
    _MANAGEMENT_URL = "https://account.jagex.com/en-GB/manage/profile"

    _GUERRILLA_MAIL_API_URL = "https://api.guerrillamail.com/ajax.php"

    def __init__(
        self,
        user_agent: str,
        element_wait_timeout: int,
        cache_update_threshold: float,
        enable_dev_tools: bool,
        account_email: str,
        account_password: str,
        proxy: models.Proxy | None = None,
        set_2fa: bool = False,
        use_headless_browser: bool = False,
        imap_details: models.IMAPDetails | None = None,
        use_proxy_for_guerrilla_mail: bool = True,
    ) -> None:
        self.user_agent = user_agent
        self.enable_dev_tools = enable_dev_tools
        self.use_headless_browser = use_headless_browser
        self.element_wait_timeout = element_wait_timeout

        self.cache_update_threshold = cache_update_threshold
        self.cache_folder = SCRIPT_DIR / "cache"

        self.proxy = proxy
        self.account_email = account_email
        self.account_username = account_email.split("@")[0]
        self.account_password = account_password
        self.set_2fa = set_2fa

        self.imap_details = imap_details
        self.use_proxy_for_guerrilla_mail = use_proxy_for_guerrilla_mail

        Settings.set_language("en")

    def _get_dir_size(self, directory: Path) -> int:
        """Return the size of a directory"""
        return sum(f.stat().st_size for f in directory.glob("**/*") if f.is_file())

    def _setup_browser_cache(self, co: ChromiumOptions, run_path: Path) -> None:
        """Copies the primary cache and sets copy for current run."""
        run_number = str(run_path).split("_")[-1]
        logger.info(f"Creating cache folder for run number: {run_number}")
        new_cache_folder = run_path / "cache"
        if self.cache_folder.is_dir():
            with self._CACHE_FOLDER_LOCK:
                shutil.copytree(self.cache_folder, new_cache_folder)
        co.set_argument(f"--disk-cache-dir={new_cache_folder}")

    def _get_new_browser(self, run_path: Path, ip: str, port: int) -> Chromium:
        """Creates a new browser tab with temp settings and an open port."""
        co = ChromiumOptions()
        co.auto_port()

        co.mute()
        # co.no_imgs()  # no_imgs() seems to cause cloudflare challenge to infinite loop

        # Disable chrome optimization features to save on bandwidth
        co.set_argument(
            "--disable-features=OptimizationGuideModelDownloading,OptimizationHintsFetching,OptimizationTargetPrediction,OptimizationHints"
        )

        self._setup_browser_cache(co, run_path=run_path)

        co.set_timeouts(self.element_wait_timeout)

        if self.user_agent:
            co.set_user_agent(self.user_agent)

        if self.use_headless_browser:
            co.set_argument("--headless")
            if not self.user_agent:
                logger.warning(
                    "Using headless without setting a user agent. This will likely get your session detected."
                )
        elif self.enable_dev_tools:
            co.set_argument("--auto-open-devtools-for-tabs")

        co.set_proxy(f"http://{ip}:{port}")

        browser = Chromium(addr_or_opts=co)
        return browser

    def _get_browser_ip(self, tab: MixTab) -> str:
        """Get the IP address that the browser is using."""
        url = "https://api64.ipify.org/?format=raw"
        if not tab.get(url):
            raise RegistrationError("Failed to get to ipify to verify our browser ip.")
        ele = tab.ele("tag:pre")
        if not ele:
            raise RegistrationError("Failed to find the ip element in the ipify text.")
        return ele.text

    def _find_element(self, tab: MixTab, identifier: str) -> ChromiumElement:
        """Find an element in the tab. Raises ElementNotFoundError."""
        logger.debug(f"Looking for element to click with identifier: {identifier}")

        logger.debug("Waiting for element to be loaded")
        if not tab.wait.eles_loaded(identifier):
            raise ElementNotFoundError(
                f"Couldn't find loaded element with identifier: {identifier}"
            )

        logger.debug("Getting element")
        element = tab.ele(identifier)
        if not element:
            raise ElementNotFoundError(f"Failed to get element: {identifier}")

        logger.debug("Waiting for element to be displayed")
        try:
            element.wait.displayed()
        except TimeoutError as e:
            raise ElementNotFoundError(
                f"Timed out waiting for element to be displayed: {identifier}"
            ) from e

        logger.debug("Returning element")
        return element

    def _click_element(self, tab: MixTab, identifier: str) -> ChromiumElement:
        """Left click the provided element."""
        element = self._find_element(tab, identifier)
        logger.debug("Clicking element")
        tab.actions.move_to(element).click()
        return element

    def _click_and_type(
        self, tab: MixTab, identifier: str, text: str, typing_interval: float = 0.01
    ) -> ChromiumElement:
        """Click the provided element and then type the text."""
        element = self._find_element(tab, identifier)
        logger.debug(f"Clicking element and then typing: {text}")
        tab.actions.move_to(element).click().type(text, interval=typing_interval)
        return element

    def _locate_cf_button(self, tab: MixTab) -> ChromiumElement | None:
        """Finds the CF challenge button in the tab."""
        logger.debug("Looking for CF checkbox.")

        for ele in tab.eles("tag:input", timeout=1):
            attrs = ele.attrs
            if not (attrs.get("type") == "hidden" and "turnstile" in attrs.get("name", "")):
                continue

            logger.debug(f"Found turnstile input: {attrs['name']}")

            try:
                container = ele.parent()
                if not container:
                    logger.debug("Couldn't get container")
                    continue

                shadow = container.shadow_root or container.child().shadow_root
                if not shadow:
                    logger.debug("Couldn't access shadow root")
                    continue

                iframe = shadow.ele("tag:iframe")
                if not iframe:
                    logger.debug("No iframe in shadow root")
                    continue

                frame = tab.get_frame(iframe)
                if not frame:
                    logger.debug("Couldn't get frame context")
                    continue

                body = frame.ele("tag:body")
                if body and body.shadow_root:
                    if checkbox := body.shadow_root.ele("tag:input"):
                        return checkbox
            except Exception as e:
                logger.debug(f"Exception locating CF checkbox: {e}")
                continue

        return None

    def _bypass_challenge(self, tab: MixTab, timeout_seconds: int = 15) -> None:
        """Attempts to bypass the CF challenge by clicking the checkbox."""
        page_title = "Just a moment"
        timeout = time.time() + timeout_seconds

        while time.time() < timeout:
            if page_title not in tab.title:
                logger.debug("No longer on the challenge page.")
                return

            button = self._locate_cf_button(tab)
            if button:
                button.click()
                logger.debug("Clicked CF checkbox.")

            time.sleep(0.5)

        raise TimeoutError("Timed out trying to bypass CF challenge.")

    def _get_verification_code_imap(
        self, imap_details: models.IMAPDetails, account_email: str, timeout_seconds: int = 30
    ) -> str:
        """Gets the verification code from catch all email via imap."""
        email_query = AND(to=account_email, seen=False)
        code_regex = r'data-testid="registration-started-verification-code"[^>]*>([A-Z0-9]+)<'
        with MailBox(imap_details.ip, imap_details.port).login(
            imap_details.email, imap_details.password
        ) as mailbox:
            timeout = time.time() + timeout_seconds
            while time.time() < timeout:
                emails = mailbox.fetch(email_query)
                for email in emails:
                    match = re.search(code_regex, email.html)
                    if match:
                        return match.group(1)
                time.sleep(0.1)
        raise RegistrationError("Timed out waiting for registration code.")

    def _get_verification_code_guerrilla_mail(
        self, account_email: str, timeout_seconds: int = 30
    ) -> str:
        """Get the verification code for the jagex account from a temp Guerrilla Mail email."""
        from datetime import timedelta

        import rnet
        from rnet.blocking import Client

        cookie_jar = rnet.Jar()
        rnet_client = Client(
            emulation=rnet.EmulationOption(
                emulation=rnet.Emulation.Chrome143,
                emulation_os=rnet.EmulationOS.Windows,
            ),
            user_agent=self.user_agent,
            cookie_provider=cookie_jar,
            timeout=timedelta(seconds=self.element_wait_timeout),
            proxies=[
                rnet.Proxy.all(
                    f"http://{self.proxy.username}:{self.proxy.password}@{self.proxy.ip}:{self.proxy.port}"
                )
            ]
            if self.proxy and self.use_proxy_for_guerrilla_mail
            else None,
        )

        logger.debug("Getting account verification code via Guerrilla mail.")

        get_email_resp = rnet_client.get(
            url=self._GUERRILLA_MAIL_API_URL,
            query={"f": "get_email_address", "lang": "en"},
        )
        logger.debug(f"Response: {get_email_resp}")
        get_email_resp.raise_for_status()

        sid_token = get_email_resp.json()["sid_token"]

        account_username = account_email.split("@")[0]

        logger.debug(f"Sending request to set Guerrilla Mail email to: {account_username}.")
        set_email_resp = rnet_client.get(
            url=self._GUERRILLA_MAIL_API_URL,
            query={
                "f": "set_email_user",
                "email_user": account_username,
                "lang": "en",
                "sid_token": sid_token,
            },
        )
        logger.debug(f"Response: {set_email_resp}")
        set_email_resp.raise_for_status()

        if account_username not in set_email_resp.json()["email_addr"]:
            raise RegistrationError("Failed to set account email on Guerrilla Mail.")

        timeout = time.time() + timeout_seconds
        while time.time() < timeout:
            logger.debug("Sending request to check our email.")
            check_email_resp = rnet_client.get(
                url=self._GUERRILLA_MAIL_API_URL,
                query={"f": "check_email", "sid_token": sid_token, "seq": 0},
            )
            logger.debug(f"Response: {check_email_resp}")
            check_email_resp.raise_for_status()

            for email in check_email_resp.json()["list"]:
                if email["mail_from"] != "no-reply@contact.jagex.com":
                    continue
                mail_subject: str = email["mail_subject"]
                return mail_subject.split()[0]
            time.sleep(1)
        raise RegistrationError("Timed out waiting for registration code.")

    def _update_cache(self, run_cache_path: Path) -> None:
        """Update primary cache if run cache is significantly different."""
        with self._CACHE_FOLDER_LOCK:
            if not self.cache_folder.is_dir():
                logger.debug("Primary cache doesn't exist. Copying run cache.")
                shutil.copytree(run_cache_path, self.cache_folder)
                return

            run_size = self._get_dir_size(run_cache_path)
            original_size = self._get_dir_size(self.cache_folder)

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

    def _handle_registration(self, browser: Chromium) -> models.JagexAccount:
        """Do the account registration flow and return a JagexAccount or raise a RegistrationError."""
        tab = browser.latest_tab
        tab.set.auto_handle_alert()

        tab.run_cdp("Network.enable")
        tab.run_cdp("Network.setBlockedURLs", urls=self._URLS_TO_BLOCK)

        browser_ip = self._get_browser_ip(tab)
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

        logger.debug(f"Going to registration url: {self._REGISTRATION_URL}")
        if not tab.get(self._REGISTRATION_URL):
            raise RegistrationError(f"Failed to go to url: {self._REGISTRATION_URL}")
        tab.wait.title_change(text="Create a Jagex account", raise_err=True)

        if "Sorry, you have been blocked" in tab.html:
            raise RegistrationError("IP is blocked by CF. Exiting.")

        self._click_and_type(tab, "@id:email", jagex_account.email)
        self._click_and_type(
            tab,
            "@id:registration-start-form--field-day",
            str(jagex_account.birthday.day),
        )
        self._click_and_type(
            tab,
            "@id:registration-start-form--field-month",
            str(jagex_account.birthday.month),
        )
        self._click_and_type(
            tab,
            "@id:registration-start-form--field-year",
            str(jagex_account.birthday.year),
        )
        self._click_element(tab, "@id:registration-start-accept-agreements")
        self._click_element(tab, "@id:registration-start-form--continue-button")
        tab.wait.doc_loaded(raise_err=True)

        if self.imap_details:
            code = self._get_verification_code_imap(self.imap_details, self.account_username)
        else:
            code = self._get_verification_code_guerrilla_mail(self.account_username)
        self._click_and_type(tab, "@id:registration-verify-form-code-input", code)
        self._click_element(tab, "@id:registration-verify-form-continue-button")
        tab.wait.doc_loaded(raise_err=True)

        self._click_and_type(tab, "@id:displayName", self.account_username)
        self._click_element(tab, "@id:registration-account-name-form--continue-button")
        tab.wait.doc_loaded(raise_err=True)

        self._click_and_type(tab, "@id:password", self.account_password)
        self._click_and_type(tab, "@id:repassword", self.account_password)
        self._click_element(tab, "@id:registration-password-form--create-account-button")
        tab.wait.doc_loaded(raise_err=True)

        tab.wait.title_change("Registration completed", raise_err=True)

        if self.set_2fa:
            logger.debug("Going to management page")
            if not tab.get(self._MANAGEMENT_URL):
                raise RegistrationError("Failed to get to the account management page.")
            tab.wait.doc_loaded(raise_err=True)

            # Wait to get to the challenge page before we attempt to solve it.
            while "Just a moment" not in tab.title:
                time.sleep(0.1)

            self._bypass_challenge(tab)

            tab.wait.url_change(self._MANAGEMENT_URL, raise_err=True)

            self._click_element(tab, "@data-testid:mfa-enable-totp-button")
            self._click_element(tab, "@id:authentication-setup-show-secret")

            setup_key_element = self._find_element(tab, "@id:authentication-setup-secret-key")
            setup_key = setup_key_element.text
            logger.debug(f"Extracted 2fa setup key: {setup_key}")

            self._click_element(tab, "@data-testid:authenticator-setup-qr-button")
            totp = pyotp.TOTP(setup_key).now()
            logger.debug(f"Generated TOTP code: {totp}")

            self._click_and_type(tab, "@id:authentication-setup-verification-code", totp)
            self._click_element(tab, "@data-testid:authentication-setup-qr-code-submit-button")

            backup_codes_element = self._find_element(
                tab, "@id:authentication-setup-complete-codes"
            )
            backup_codes = backup_codes_element.text.split("\n")
            logger.debug(f"Got 2fa backup codes: {backup_codes}")

            jagex_account.tfa = models.TwoFactorAuth(setup_key=setup_key, backup_codes=backup_codes)

        logger.info("Registration finished")
        return jagex_account

    def register_account(self) -> models.JagexAccount:
        """Wrapper function to fully register a Jagex account."""
        run_number = random.randint(10_000, 65_535)
        run_path = SCRIPT_DIR / f"run_{run_number}"
        run_path.mkdir()

        gproxy = GProxy(upstream_proxy=self.proxy, allowed_hosts=["jagex", "cloudflare", "ipify"])
        gproxy.start()

        browser = self._get_new_browser(run_path, gproxy.ip, gproxy.port)

        success = False
        try:
            account = self._handle_registration(browser=browser)
            success = True
            return account
        finally:
            self._cleanup(
                run_path=run_path, browser=browser, gproxy=gproxy, update_primary_cache=success
            )
