# dns-resolver

This is my personal project creating DNS resolver for my android vpn.

This DNS resolver has a blocklist which where user can add web url to the blocklist or delete the url from blocklist. It also has a cache feature to increase performance. 

This DNS resolver works more or less like this:
1. User inputs a URL in the Android browser.
2. The phone send dns message to this resolver, and checks whether the URL is in the blocklist or not. If not, it caches the URL first, then sends the URL to the Cloudflare DNS service (or any other DNS service). Every response from DNS service passed directly to the user.
