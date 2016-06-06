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
 * @version 1.0
 */



/*
 * Begin Configuration
 */

/**
 * Determines whether the protection should run or not.
 * Set to true to enable Betwixt's protection.
 * If disabled all checks will pass regardless of validity
 */
$GLOBALS['betwixt']['enabled'] = true;//Default: True

/**
 * Enter the file name of a html file for what you would like to display while
 * the script is running. The file must be local to betwixt.php
 */
$GLOBALS['betwixt']['displayPage'] = "checking.html";

/**
 * Declares the client's IP used for anti-spoofing and anti-token-stealing
 * precautions, change this variable to something you can trust. The default
 * value will work for 95% of installations.
 */
$GLOBALS['betwixt']['ipSource'] = $_SERVER['REMOTE_ADDR'];//Default: $_SERVER['REMOTE_ADDR']

/**
 * A secret key used in hashing. Please generate a random string and
 * place it here. If you change this value, all previously generated tokens
 * will become invalid.
 * Leaving this to false will allow Betwixt to write it's own key
 */
$GLOBALS['betwixt']['key'] = false;//Default: False

/**
 * Locks a token to a browser's user agent, can assist in preventing
 * a few attacks for either brute forcing tokens, or stealing a token
 * Setting to true adds more security
 */
$GLOBALS['betwixt']['userAgentLock'] = true;//Default: True

///// COOKIE SETTINGS /////

/**
 * Cookie Prefix, Allows a selection of text to be prefixed to the cookie
 * (Example: YourText_tokenid:xxx)
 */
$GLOBALS['betwixt']['cookiePrefix'] = "Betwixt";//Default: Betwixt

/**
 * Cookie Expiry, Defines how long the cookie is valid for.
 * Defined in seconds, 43200 seconds = 12 hours and is likely the best choice
 * for most websites.
 */
$GLOBALS['betwixt']['cookieExpiry'] = 43200;//Default: 43200

/**
 * Cookie Path, the path on the server in which the token will be valid for.
 * If set to '/', the cookie will be available within the entire domain.
 * If set to '/foo/', the cookie will only be available within the /foo/ directory.
 */
$GLOBALS['betwixt']['cookiePath'] = '/';//Default: /

/**
 * Cookie Domain, This is where you should implement your website's domain,
 * This is used to prevent the token from being leaked to other websites
 */
$GLOBALS['betwixt']['cookiePath'] = "";//Example: binaryevolved.com

/**
 * Secure Cookies, Sets the token to only be transmitted when connecting via a HTTPs connection.
 * This is a rather useful security option for those with encryption based concerns
 */
$GLOBALS['betwixt']['cookieSecure'] = false;//Best Use: True


/*
 * End Configuration
 * Begin Functions
 */


function btwxt_CheckToken(){
    $tokenID = $_COOKIE[btwxt_CraftCookieName('ID')];
    $tokenData = $_COOKIE[btwxt_CraftCookieName('Token')];
    $tokenTime = $_COOKIE[btwxt_CraftCookieName('Timestamp')];
    $serverToken = $tokenID.'|'.$tokenTime.'|'.$GLOBALS['betwixt']['ipSource'];
    if ($GLOBALS['betwixt']['userAgentLock']) $serverToken .= '|'.$_SERVER['HTTP_USER_AGENT'];
    $serverToken = btwxt_HashKey($serverToken);
    if (!$GLOBALS['betwixt']['enabled']) return true;
    if (hash_equals($serverToken, $tokenData)){
        if ($tokenTime < time()) return false;
        return true;
    }else{
        return false;
    }//If all else fails, fail script

}


function btwxt_CraftCookieName($cookieID){
    return $GLOBALS['betwixt']['cookiePrefix'].'_'.$cookieID;
}

function btwxt_Imprint(){
    $tokenID = bin2hex(openssl_random_pseudo_bytes(5));//Generates a token ID
    $expiryTime = time() + $GLOBALS['betwixt']['cookieExpiry'];
    $tokenValue = $tokenID.'|'.$expiryTime.'|'.$GLOBALS['betwixt']['ipSource'];
    if ($GLOBALS['betwixt']['userAgentLock']) $tokenValue .= '|'.$_SERVER['HTTP_USER_AGENT'];
    $cookieToken = btwxt_HashKey($tokenValue);
    if (!$cookieToken)return false;
    $domainPath = $GLOBALS['betwixt']['cookiePath'] == '' ? false : $GLOBALS['betwixt']['cookiePath'];
    setcookie (btwxt_CraftCookieName('ID'), $tokenID, $expiryTime, $GLOBALS['betwixt']['cookiePath'], $domainPath,
               $GLOBALS['betwixt']['cookieSecure'], true);
    setcookie (btwxt_CraftCookieName('Token'), $cookieToken, $expiryTime, $GLOBALS['betwixt']['cookiePath'], $domainPath,
               $GLOBALS['betwixt']['cookieSecure'], true);
    setcookie (btwxt_CraftCookieName('Timestamp'), $expiryTime, $expiryTime, $GLOBALS['betwixt']['cookiePath'], $domainPath,
               $GLOBALS['betwixt']['cookieSecure'], true);
    return true;
}

function btwxt_HashKey($input){
    $key = btwxt_GetKey();
    if (!$key){
        trigger_error ('Betwixt: Unable to retrieve a safe key');
        return false;
    }
    $output = hash_hmac('sha512', $input, $key);
    return $output;
}

function btwxt_GetKey() {
    if ($GLOBALS['betwixt']['key']) return $GLOBALS['betwixt']['key'];
    $file = dirname(__FILE__).'/'.'/betwixt-key.php';
    $key = '';//Pleases IDEs
    if (file_exists($file)) {
        include $file;
        return hex2bin($key);
    }
    if (is_writable(dirname(__FILE__))) {
        $key = bin2hex(openssl_random_pseudo_bytes(256));
        $fh = fopen($file, 'w');
        fwrite($fh, '<?php $key = "'.$key.'";' . PHP_EOL);
        fclose($fh);
        return $key;
    }
    return false;
}

/*
 * End Functions
 * Begin Initialization
 */
if ($GLOBALS['betwixt']['enabled']) {//Check if Betwixt is enabled, and allowed to run
    if (isset ($_COOKIE[btwxt_CraftCookieName("ID")]) && isset ($_COOKIE[btwxt_CraftCookieName("Token")])
        && isset ($_COOKIE[btwxt_CraftCookieName("Timestamp")])){//Checks if a Betwixt token has been declared for the user
        if (!btwxt_CheckToken()){
            setcookie(btwxt_CraftCookieName('ID'), "", time()-3600);
            setcookie(btwxt_CraftCookieName('Token'), "", time()-3600);
            setcookie(btwxt_CraftCookieName('Timestamp'), "", time()-3600);
            echo "Error- Your Betwixt Validation Token is invalid. You have either forged a token, or have been idle too
            long. Try to refresh the page. If this error continues to occur, contact the webmaster. Please ensure you have enabled cookies.";

        }
    }else{
        //Creates a set of tokens for validation
        if (!btwxt_Imprint()){
            echo "<h1>An error occurred, please ensure you have cookies enabled</h1>";
            echo "<br><p>-Betwixt</p>";
        }else{

        //Render page
        $include = dirname(__FILE__).'/'.$GLOBALS['betwixt']['displayPage'];
        include($include);
        //Token is created, Refresh page to re-run the check
        echo '<meta http-equiv="refresh" content="3">';
        die();//Stop the rest of the page from rendering.
        }
    }
}