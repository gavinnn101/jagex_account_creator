# Jagex Account Creator
Utilizes the Python DrissionPage library to automate a Chrome browser and sign up for a new Jagex account.

## Notable features:
* Takes ~15 seconds per account without 2FA enabled. 
* Takes ~30 seconds per account with 2FA enabled.
* Multi-threaded - You can make as many accounts as you want in 15-30 seconds as long as you have computer resources / proxies to handle the threads!
* Supports running the browser in headless mode.
* ~10MB of data usage pre-cache, 900kb of data usage post-cache!
* * Sets up a local proxy server that intercepts all of the Chrome traffic and blocks requests that aren't required.
* * Elements that can't be blocked are saved to a cache that is shared by all runs and frequently updated.
* Two options for account email:
* * Utilize a catch-all email via imap.
* * Utilize the Guerrilla Mail temp email service.
* Supports enabling TOTP 2FA on created accounts.
* Each successful account creation appends the account and all of the registration info used to `accounts.json`.

## Notable not-features
* If for some reason the creator fails during a run, it likely won't cleanup the temporary run folder it creates.
* * A failed run in headless mode will leave behind a chrome process that you'll need to end.
* If you get a Cloudflare checkbox, it is almost certainly one of two options:
* * Your Chrome's user-agent found at `chrome://version` doesn't match the `USER_AGENT` constant in the script.
* * Your IP is (temporarily) flagged.
* * The script will click the cf turnstile checkbox to continue with account registration.
* It's possible for the randomly generated username to be `not allowed` by Jagex which will make the creation fail.
* * I feel like I've seen the list of restrictions somewhere when looking at the requests but can't remember.
* * The ideal fix would be to create a username accounting for those restrictions.

## Setup

* Download the repository - https://github.com/gavinnn101/jagex_account_creator/archive/refs/heads/main.zip
* * Unzip the download to the location of your choice.
* Setup `uv` if not already - https://docs.astral.sh/uv/getting-started/installation/
* Open `$script_root\src\config.toml` and edit the settings accordingly.
* * Ensure the `user_agent` string at `chrome://version` in your browser matches the `user_agent` string in the config.
* * Set either `use_imap` or `use_guerrilla_mail` to `true`.
* * * Set `email.guerrilla_mail` or `email.imap` settings accordingly.
* * `account.password`
* * Enable `proxies` and setup list if being used.
* Open a terminal in the root folder of your download:
* * Run `cd src`.
* * Run `uv run main.py`.

### IMAP / Domains Explanation
Your `imap.email` should have a catch-all alias pointing to it for all domains listed under `account.domains`
```
[email.imap]
domains = ["mydomain1.com", "myotherdomain.net"]

[imap]
email = "catchAll@mydomain.com"

> Account creator tries to make abcd123@mydomain1.com
> Account creator signs into catchAll@mydomain.com via imap and waits for an email addressed to abcd123@mydomain1.com.

> Account creator tries to make abcd123@myotherdomain.net
> Account creator signs into catchAll@mydomain.com via imap and waits for an email addressed to abcd123@myotherdomain.net.
```

To achieve this functionality I would:
* Self host [docker-mailserver](https://github.com/docker-mailserver/docker-mailserver)
* Purchase email hosting from [mxroute](https://mxroute.com/)
* * (Not afilliated, don't add me for support.)
* Pay for [EternalFarm](https://eternalpayments.selly.store/category/12bd08e1) because they host an account creator for you.
* * (Not afilliated, don't add me for support.)
* Replace functionality with browsing to a temp email service instead. (will use more bandwidth, be slower, etc.)

### Guerrilla Mail Explanation
Guerrilla Mail is a temporary email service that has multiple free domains to use to receive emails. The script can utilize the Guerrilla Mail API to set a temporary email and use it for registration. The benefit of this is you don't need IMAP setup, custom domains, etc.

If using Guerrilla Mail in the script, the script will generate a random string as the username, choose a random domain from `email.guerrilla_mail.list`, and use that as the account's registration email.

# Contact
My only discord is `gavinnn` (uid: `132269908628078592`)
