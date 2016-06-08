Betwixt \- To stand in between
=======


**Betwixt** is a system designed to integrate into websites to help prevent automated submissions for website requests and bots/malicious scripts from being able to access and load resources.

**How to use:**
-----------
Betwixt is designed to be a drop in way to safely manage verification cookies used in safety checks in the process of determining a user's malicious intent for websites.
Simply drop betwixt.php into any directory and then include it using `include ('betwixt.php')`(See test.php for an example)
Next you should go through and check the configuration options located at the top of php class. Most settings work best at default, others are disabled for easy drop in usage for most environments.

At the bottom of `betwixt.php` you will find a basic integration which does not perform any checks by its self. This is where you could integrate your own form of checks required to be issued a session token.

As the project continues on, I plan to add several default implemented security measures like captcha requirements to get past the Betwixt screen.


**Security:**
---------
Betwixt uses cryptographic hashing to ensure expiry of token and ensure that tokens can only be issue by the server and can't be generated or "spoofed" on the client side. Betwixt uses `SHA512-HMAC` and a 2048 bit private key (generated if not specified) to "key" the hashes. Without this key an attacker could not generate any valid token to bypass the system. 