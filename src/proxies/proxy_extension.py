# https://github.com/g1879/DrissionPage/issues/462#issuecomment-2561864526
import os
import random
import string


def create_proxy_extension(
    proxy_host,
    proxy_port,
    proxy_username=None,
    proxy_password=None,
    scheme="http",
    plugin_path=None,
):
    """
    Creates a Chrome extension for proxy configuration with optional authentication.

    Parameters:
    proxy_host (str): Proxy server hostname or IP
    proxy_port (str): Proxy server port
    proxy_username (str, optional): Username for proxy authentication. If None, no auth is set up.
    proxy_password (str, optional): Password for proxy authentication. If None, no auth is set up.
    scheme (str, optional): Proxy protocol (http, https, socks4, socks5)
    plugin_path (str, optional): Custom path to create the extension. Random if None.

    Returns:
    str: Path to the created extension
    """
    # Create Chrome extension manifest.json content
    manifest_json = """
    {
        "version": "1.0.0",
        "manifest_version": 3,
        "name": "proxy",
        "permissions": [
            "proxy",
            "tabs",
            "unlimitedStorage",
            "storage",
            "webRequest",
            "webRequestAuthProvider"
        ],
        "host_permissions": [
            "<all_urls>"
        ],
        "background": {
            "service_worker": "background.js"
        },
        "minimum_chrome_version":"88.0.0"
}
"""

    # Base proxy configuration JavaScript
    proxy_config_js = string.Template("""
        var config = {
            mode: "fixed_servers",
            rules: {
                singleProxy: {
                    scheme: "${scheme}",
                    host: "${host}",
                    port: parseInt(${port})
                },
                bypassList: ["localhost"]
            }
        };

        chrome.proxy.settings.set({value: config, scope: "regular"}, function() {});
    """).substitute(
        host=proxy_host,
        port=proxy_port,
        scheme=scheme,
    )

    # Authentication JavaScript - only included if username and password are provided
    auth_js = ""
    if proxy_username and proxy_password:
        auth_js = string.Template("""
        function callbackFn(details) {
            return {
                authCredentials: {
                    username: "${username}",
                    password: "${password}"
                }
            };
        }

        chrome.webRequest.onAuthRequired.addListener(
            callbackFn,
            {urls: ["<all_urls>"]},
            ['blocking']
        );
        """).substitute(username=proxy_username, password=proxy_password)

    # Combine the JavaScript parts
    background_js = proxy_config_js + auth_js

    # Create extension directory
    if not plugin_path:
        plugin_path = "/tmp/" + str(random.randint(0000, 9999))
    os.makedirs(plugin_path, exist_ok=True)

    # Write manifest.json and background.js files
    with open(os.path.join(plugin_path, "manifest.json"), "w+") as f:
        f.write(manifest_json)
    with open(os.path.join(plugin_path, "background.js"), "w+") as f:
        f.write(background_js)

    return plugin_path
