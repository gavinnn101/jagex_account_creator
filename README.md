# Jagex Account Creator
Utilizes the Python DrissionPage library to automate a Chrome browser and sign up for a new Jagex account.

## Notable features:
* Takes ~15 seconds per account without 2FA enabled. 
* Takes ~30 seconds per account with 2FA enabled.
* Multi-threaded - You can make as many accounts as you want in 15-30 seconds as long as you have computer resources / proxies to handle the threads!
* Supports headless mode.
* ~10MB of data usage pre-cache, 900kb of data usage post-cache!
* * Sets up a local proxy server that intercepts all of the Chrome traffic and blocks requests that aren't required.
* * Elements that can't be blocked are saved to a cache that is shared by all runs and frequently updated.
* Utilizes a catch-all email via imap for easy and quick account verification.
* * All domains used for accounts should point to the single catch-all email being used with imap.
* Supports enabling OTP 2FA on accounts.

## Notable not-features
* If for some reason the creator fails during a run, it likely won't cleanup the temporary run folder it creates.
* If you get a Cloudflare checkbox, your IP is likely temporarily flagged.
* * There is an idea to always check for a Cloudflare checkbox and solve it but it's not implemented as you should be rotating IPs anyways.

# Contact
My only discord is `gavinnn`.
