<?php

/**
 * Betwixt, A PHP Based system to help regulate bots, and malicious users.
 * https://github.com/BinaryEvolved/Betwixt
 * ---
 * Written for PHP 5.6
 * @author BinaryEvolved https://github.com/BinaryEvolved/Betwixt
 * @copyright BinaryEvolved 2016, Licensed under GNU GENERAL PUBLIC LICENSE v3 | https://github.com/BinaryEvolved/Betwixt/blob/master/LICENSE
 * @deprecated This file is meant to be included on any page that requires it's protection. (Ex: include(betwixt.php);)
 *  Once included it's code will automatically run and perform it's protection checks.
 */
class Betwixt
{


    private $config = array();
    public $reCaptcha;

    public function __construct()
    {
        /*
         * Begin Configuration
        */
        /**
         * Determines whether the protection should run or not.
         * Set to true to enable Betwixt's protection.
         * If disabled all checks will pass regardless of validity
         */
        $this->config['enabled'] = true;//Default: True

        /**
         * Enter the file name of a html file for what you would like to display while
         * the script is running. The file must be local to betwixt.php
         */
        $this->config['displayPage'] = "checking.html";

        /**
         * Declares the client's IP used for anti-spoofing and anti-token-stealing
         * precautions, change this variable to something you can trust. The default
         * value will work for 95% of installations.
         */
        $this->config['ipSource'] = $_SERVER['REMOTE_ADDR'];//Default: $_SERVER['REMOTE_ADDR']

        /**
         * A secret key used in hashing. Please generate a random string and
         * place it here. If you change this value, all previously generated tokens
         * will become invalid.
         * Leaving this to false will allow Betwixt to write it's own key
         */
        $this->config['key'] = false;//Default: False

        /**
         * Locks a token to a browser's user agent, can assist in preventing
         * a few attacks for either brute forcing tokens, or stealing a token
         * Setting to true adds more security
         */
        $this->config['userAgentLock'] = true;//Default: True

        ///// VERIFICATION SETTINGS /////

        /**
         * Enables Google's reCaptcha noCaptcha system, this captcha will
         * be required to be passed in order to gain access past betwixt
         */
        $this->config['reCaptcha']['enabled'] = true;

        /**
         * Enter your website's reCaptcha 'Site Key' here,
         * You can sign up for one here: https://www.google.com/recaptcha/admin
         */
        $this->config['reCaptcha']['siteKey'] = '6Lfa5SUTAAAAAB-YgY2lDYs6ooYdbVGXypJMQJea';

        /**
         * Enter your website's reCaptcha 'Secret Key' here,
         * You can sign up for one here: https://www.google.com/recaptcha/admin
         */
        $this->config['reCaptcha']['secretKey'] = '6Lfa5SUTAAAAAA4kV6VBjJ6EK1TBUrKJuYYlL8HA';

        /**
         * Changes the theme assigned to your reCaptcha Widget
         * Possible Options: light, dark
         */
        $this->config['reCaptcha']['theme'] = 'light';//Either light or dark

        ///// COOKIE SETTINGS /////

        /**
         * Cookie Prefix, Allows a selection of text to be prefixed to the cookie
         * (Example: YourText_tokenid:xxx)
         */
        $this->config['cookiePrefix'] = "Betwixt";//Default: Betwixt

        /**
         * Cookie Expiry, Defines how long the cookie is valid for.
         * Defined in seconds, 43200 seconds = 12 hours and is likely the best choice
         * for most websites.
         */
        $this->config['cookieExpiry'] = 43200;//Default: 43200

        /**
         * Cookie Path, the path on the server in which the token will be valid for.
         * If set to '/', the cookie will be available within the entire domain.
         * If set to '/foo/', the cookie will only be available within the /foo/ directory.
         */
        $this->config['cookiePath'] = '/';//Default: /

        /**
         * Cookie Domain, This is where you should implement your website's domain,
         * This is used to prevent the token from being leaked to other websites
         */
        $this->config['cookiePath'] = "";//Example: binaryevolved.com

        /**
         * Secure Cookies, Sets the token to only be transmitted when connecting via a HTTPs connection.
         * This is a rather useful security option for those with encryption based concerns
         */
        $this->config['cookieSecure'] = false;//Best Use: True
        /*
        * End Configuration
        * Begin Functions
        */

        if ($this->config['reCaptcha']['enabled']){
            include('recaptcha.php');
            $this->reCaptcha = new ReCaptcha($this->config['reCaptcha']['secretKey']);
        }

    }


    /**
     * Checks for three cookies and ensures they are valid, returns true or false depending on validity of tokens
     * @return bool
     */
    public function CheckToken()
    {
        //Declared the variables we will work with
        $tokenID = $_COOKIE[$this->CraftCookieName('ID')];
        $tokenData = $_COOKIE[$this->CraftCookieName('Token')];
        $tokenTime = $_COOKIE[$this->CraftCookieName('Timestamp')];
        //Combine the server token to be hashed
        $serverToken = $tokenID . '|' . $tokenTime . '|' . $this->config['ipSource'];
        if ($this->config['userAgentLock']) $serverToken .= '|' . $_SERVER['HTTP_USER_AGENT'];

        $serverToken = $this->HashKey($serverToken);//Hash the token
        if (!$this->config['enabled']) return true;//Return true if disabled
        if (hash_equals($serverToken, $tokenData)){//If cookie sent matches token hashed locally
            if ($tokenTime < time()) return false;
            return true;
        }
        else{
            return false;
        }

    }

    /**
     * Formats a cookie name depending on the global configuration
     * @param $cookieID
     * @return string
     */
    public function CraftCookieName($cookieID)
    {
        return $this->config['cookiePrefix'] . '_' . $cookieID;
    }

    /**
     * Hashes and keys several values togethers and sets them into three different cookies. Returns false on failure
     * @return bool
     */
    public function Imprint()
    {
        $tokenID = bin2hex(openssl_random_pseudo_bytes(10));//CPRNG for the ID
        $expiryTime = time() + $this->config['cookieExpiry'];//Calculate the expiry time
        //Figure out the token hash
        $tokenValue = $tokenID . '|' . $expiryTime . '|' . $this->config['ipSource'];
        if ($this->config['userAgentLock']) $tokenValue .= '|' . $_SERVER['HTTP_USER_AGENT'];
        $cookieToken = $this->HashKey($tokenValue);//Hash the server sided values into a token

        if (!$cookieToken) return false;//If hashing failed return false
        $domainPath = $this->config['cookiePath'] == '' ? false : $this->config['cookiePath'];//Figure out cookie path
        //Send cookies to client to be stored
        setcookie($this->CraftCookieName('ID'), $tokenID, $expiryTime, $this->config['cookiePath'], $domainPath,
                  $this->config['cookieSecure'], true);
        setcookie($this->CraftCookieName('Token'), $cookieToken, $expiryTime, $this->config['cookiePath'], $domainPath,
                  $this->config['cookieSecure'], true);
        setcookie($this->CraftCookieName('Timestamp'), $expiryTime, $expiryTime, $this->config['cookiePath'], $domainPath,
                  $this->config['cookieSecure'], true);
        return true;//Didn't crash, good 'nouf
    }

    /**
     * Hashs and keys input into a hash, fails if unable to retrieve key
     * @param $input
     * @return bool|string
     */
    public function HashKey($input)
    {
        $key = $this->GetKey();//Pulls key from function
        if (!$key){
            trigger_error('Betwixt: Unable to retrieve a safe key');
            return false;
        }
        $output = hash_hmac('sha512', $input, $key);//Hash the input and key it with the retrieved key
        return $output;//I hope I don't need to explain this
    }

    /**
     * Returns key, if key global variable is empty it creates and reads a 2048 bit key itself.
     * Sub-note: You should only ever pull the key from this function!
     * @return bool|string
     */
    private function GetKey()
    {
        if ($this->config['key']) return $this->config['key'];//If key is defined, use that, instead use file method
        $file = dirname(__FILE__) . '/' . '/betwixt-key.php';
        $key = '';//Pleases IDEs, thank you PHPStorm for being unable to assume some values
        //can be included. If this is possible please contact me, I will give you a dollar in BitCoin..
        if (file_exists($file)){//Does key already exist?
            //Yes? Use the key in that file
            include $file;
            return hex2bin($key);
        }
        if (is_writable(dirname(__FILE__))){
            //No? Create your own key!
            $key = bin2hex(openssl_random_pseudo_bytes(256));
            $fh = fopen($file, 'w');
            fwrite($fh, '<?php $key = "' . $key . '";' . PHP_EOL);
            fclose($fh);
            return $key;
        }
        return false;//Something went wrong, return false
    }

    /**
     * Returns the status of reCaptcha being setup in the configuration of Betwixt
     * @return bool
     */
    public function IsReCaptchaEnabled()
    {
        return $this->config['reCaptcha']['enabled'];
    }

    /**
     * Returns siteKey specified in the Betwixt configuration
     * @return string
     */
    public function GetReCaptchaSiteKey()
    {
        return $this->config['reCaptcha']['siteKey'];
    }

    /**
     * Returns visitors's real IP based off the value specified in the Betwixt configuration
     * @return string
     */
    public function GetClientIP()
    {
        return $this->config['ipSource'];
    }

    /**
     * Checks if the client has the proper cookies set, does not validate the cookies.
     * @return bool
     */
    public function IsActive()
    {
        if (isset ($_COOKIE[$this->CraftCookieName("ID")])//Does ID exist?
            && isset ($_COOKIE[$this->CraftCookieName("Token")])//Does Token exist?
            && isset ($_COOKIE[$this->CraftCookieName("Timestamp")])//I will leave this one to you
        ){
            return true;
        }
        else{
            return false;
        }
    }

    /**
     * Removes the cookies set originally
     */
    public function RemoveToken()
    {
        setcookie($this->CraftCookieName('ID'), "", 1);
        setcookie($this->CraftCookieName('Token'), "", 1);
        setcookie($this->CraftCookieName('Timestamp'), "", 1);
    }

    /**
     * Returns the config setting for the display page
     * @return string
     */
    public function GetDisplayPage()
    {
        return $this->config['displayPage'];//Return the config value
    }


    /**
     * Returns the enabled status as set in the config
     * @return string
     */
    public function IsEnabled()
    {
        return $this->config['enabled'];//Return the config value
    }
}

/*
 * End Functions
 * Begin Initialization
 */
$betwixt = new Betwixt();

if ($betwixt->IsEnabled()){//Check if Betwixt is enabled, and allowed to run
    if ($betwixt->IsActive()){//Checks if a Betwixt token has been declared for the user
        if (!$betwixt->CheckToken()){
            $betwixt->RemoveToken();
            echo "Error- Your Betwixt Validation Token is invalid. You have either forged a token, or have been idle too
            long. Try to refresh the page. If this error continues to occur, contact the webmaster. Please ensure you have enabled cookies.";
            die();//Kill the rest of the page to prevent sensitive material from loading

        }
    }
    else{
        if ($betwixt->IsReCaptchaEnabled())//Checks if reCaptcha was enabled in the Betwixt configuration
        {
            if (isset($_POST["g-recaptcha-response"])){//Checks if reCaptcha has been submitted
                //Checks the reCaptcha API to verify a valid response was submitted
                $response =
                    $betwixt->reCaptcha->verifyResponse($betwixt->GetClientIP(), $_POST["g-recaptcha-response"]);

                if ($response->success){
                    $betwixt->Imprint();//If valid captcha was filled out, grant access to website
                    die ('<meta http-equiv="refresh" content="0">');
                }
                else{
                    die("Error- Your reCaptcha noCaptcha token has either been forged or expired because you waited too long to 
            continue.. Please refresh and try again.");
                }

            }
            else{
                //reCaptcha has yet to be filled out, instead renders the check page
                $include = dirname(__FILE__) . '/' . $betwixt->GetDisplayPage();
                include($include);
                die();//Stop the rest of the page from executing.
            }

        }
        else{//If ReCaptcha is not enabled
            //Creates a set of tokens for validation
            if (!$betwixt->Imprint()){
                echo "<h1>An error occurred, please ensure you have cookies enabled</h1>";
                echo "<br><p>-Betwixt</p>";
            }
            else{

                //Render page
                $include = dirname(__FILE__) . '/' . $betwixt->GetDisplayPage();
                include($include);
                //Token is created, Refresh page to re-run the check
                echo '<meta http-equiv="refresh" content="3">';
                die();//Stop the rest of the page from executing.
            }
        }
    }
}