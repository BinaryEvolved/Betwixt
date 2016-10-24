Betwixt \- To stand in between
=======


**Betwixt** is a system designed to integrate into websites to help prevent automated submissions for website requests and bots/malicious scripts from being able to access and load resources.

**How to use:**
-----------
Betwixt is designed to be a drop in way to safely manage verification cookies used in safety checks in the process of determining a user's malicious intent for websites.
Simply drop betwixt.php into any directory and then include it using `include ('betwixt.php')`(See test.php for an example)
Next you should go through and check the configuration options located at the top of php class. Most settings work best at default, others are disabled for easy drop in usage for most environments.

At the bottom of `betwixt.php` you will find a basic integration which does not perform any checks by its self. There is a simple reCaptcha implementation for basic security, instructions for use are below. This is where you could integrate your own form of checks required to be issued a session token.



**How to enable reCaptcha:**
-----------
Betwixt contains a simple way to require a Google reCaptcha noCaptcha to be validly completed before being granted access to the main website. All that is required is for a user to edit`betwixt.php` and scroll to the `VERIFICATION SETTINGS` configuration section (around line 65).
Here you can find the reCaptcha noCaptcha settings, to enable reCaptcha you will want to signup here: https://www.google.com/recaptcha/admin
After signing up you will receive a Site Key and Secret Key. You can then proceed to add the keys to your configuration file on Betwixt. Replace `siteKeyHere` and `secretKeyHere` with their respective keys provided from the reCaptcha signup page.
Then simply change `['enabled'] = false;` to `['enabled'] = true;`and you should be off to the races!

**NOTE:** You may be required to implement reCaptcha's widget on customized checking pages. The default Betwixt `check.html` already has been setup to automatically display the reCaptcha widget propperly. How to set this up on your custom page is beyond the scope of this readme. However it may prove useful to understand and take advantage of the fact that the `$betwixt` class is fully declared and in scope at time of the checking page's execution.


**Security:**
---------
Betwixt uses cryptographic hashing to ensure expiry of token and ensure that tokens can only be issue by the server and can't be generated or "spoofed" on the client side. Betwixt uses `SHA512-HMAC` and a 2048 bit private key (generated if not specified) to "key" the hashes. Without this key an attacker could not generate any valid token to bypass the system. 
