# Jagex Account Creator
Utilizes the Python DrissionPage library to automate a Chrome browser and sign up for a new Jagex account.

## Notable features:
* Takes ~15 seconds per account without 2FA enabled. 
* Takes ~25 seconds per account with 2FA enabled.
* Multi-threaded - You can make as many accounts as you want in 15-25 seconds as long as you have computer resources / proxies to handle the threads!
* Supports running the browser in headless mode.
* ~5MB of data usage pre-cache, ~1MB of data usage post-cache!
  * Sets up a local proxy server that intercepts all of the Chrome traffic and blocks requests that aren't required.
  * Elements that can't be blocked are saved to a common Chrome cache.
    * Each account creation copies the cache to use.
    * If the new run's cache size is greater than the difference set in the config, the common cache will be updated.
* Three options for account email:
  * Utilize a catch-all email via imap.
  * Utilize the Guerrilla Mail temp email service.
  * Utilize the Xitroo temp email service.
* Supports enabling TOTP 2FA on created accounts.
* Each successful account creation appends the account details to `accounts.jsonl`.

## Notable not-features
* If for some reason the creator fails from an uncaught exception, it likely won't cleanup the temporary run folder it creates.
  * A failed run in headless mode will leave behind a chrome process that you'll need to end.
* If you get a Cloudflare checkbox, it is almost certainly one of two options:
  * Your Chrome's user-agent found at `chrome://version` doesn't match `[browser] user_agent` in `config.toml`.
  * Your IP is (temporarily) flagged.
  * The script will click the cf turnstile checkbox to continue with account registration.
* It's possible for the randomly generated username to be `not allowed` by Jagex which will make the creation fail.
  * I feel like I've seen the list of restrictions somewhere when looking at the requests but can't remember.
  * The ideal fix would be to create a username accounting for those restrictions.

## Setup

* Download the repository - https://github.com/gavinnn101/jagex_account_creator/archive/refs/heads/main.zip
  * Unzip the download to the location of your choice.
* Setup `uv` if not already - https://docs.astral.sh/uv/getting-started/installation/
* Open `.\jagex_account_creator\config.toml` and edit the settings accordingly.
  * Ensure the `user_agent` string at `chrome://version` in your browser matches the `user_agent` string in the config.
  * Set `mail_provider` to `xitroo`, `guerrilla_mail`, or `imap`.
    * Set `email.imap` settings accordingly if using `imap`.
  * `[account] password`
    * `""` will use a unique, secure string for each account.
    * Otherwise, set a default password that'll be used for all accounts.
  * Enable `proxies` and setup list if being used.
* Open a terminal @ `.\jagex_account_creator\`:
  * Run `uv run main.py`.

### Email Providers Explained

#### IMAP
Your `imap.email` should have a catch-all alias pointing to it for all domains listed under `imap.domains`
```
[email.imap]
email = "catchAll@mydomain.com"
domains = ["mydomain1.com", "myotherdomain.net"]

> Account creator tries to make abcd123@mydomain1.com
> Account creator signs into catchAll@mydomain.com via imap and waits for an email addressed to abcd123@mydomain1.com.

> Account creator tries to make abcd123@myotherdomain.net
> Account creator signs into catchAll@mydomain.com via imap and waits for an email addressed to abcd123@myotherdomain.net.
```

To achieve this functionality I would:
* Self host [docker-mailserver](https://github.com/docker-mailserver/docker-mailserver)
* Purchase email hosting from [mxroute](https://mxroute.com/)
  * (Not affiliated, don't add me for support.)
* Pay for [EternalFarm](https://eternalpayments.selly.store/category/12bd08e1) because they host an account creator for you.
  * (Not affiliated, don't add me for support.)

#### Temp email services
* [Guerrilla Mail](https://www.guerrillamail.com/) is a free temporary email service that has multiple domains to use to receive emails.
* [Xitroo](https://xitroo.com/) is a popular temporary email service, similar to Guerrilla Mail.
* Both services use the Jagex account's username for the email username.
  * The usernames are securely generated using the `secrets` library but note that anyone can access the account's inbox using these providers if they know the username.

# Contact
Join the community Discord server for suggestions, help, etc: https://discord.gg/UHhK4kHuec
My only discord is `gavinnn` (uid: `132269908628078592`)

# Donate

Don't feel obligated, but if you really want to, I appreciate that you find the project useful enough to want to donate.
[![BuyMeACoffee](https://raw.githubusercontent.com/pachadotdev/buymeacoffee-badges/main/bmc-blue.svg)](https://www.buymeacoffee.com/gavinnn101)
