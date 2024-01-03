<?php

$ALLOW_ADMIN_EMAIL_LOGIN_ROUNDCUBE = (preg_match(
  "/^(yes|y)+$/i",
  $_ENV["ALLOW_ADMIN_EMAIL_LOGIN_ROUNDCUBE"]
));

// prevent if feature is disabled
if (!$ALLOW_ADMIN_EMAIL_LOGIN_ROUNDCUBE) {
  header('HTTP/1.0 403 Forbidden');
  echo "this feature is disabled";
  exit;
}



require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/prerequisites.inc.php';
$login = html_entity_decode(rawurldecode($_GET["login"]));

// check if dual_login is active
$is_dual = (!empty($_SESSION["dual-login"]["username"])) ? true : false;
$UserSession = $is_dual === false && $login == $_SESSION['mailcow_cc_username'];

$AuthUsers = array("admin", "domainadmin");
$AdminSession = in_array($_SESSION['mailcow_cc_role'], $AuthUsers) && $ALLOW_ADMIN_EMAIL_LOGIN !== 0;

if (!$UserSession && !$AdminSession) {
    header('HTTP/1.0 403 Forbidden');
    echo ("Not user or admin");
    exit();
}

if ($UserSession && user_get_alias_details($login) === false) {
    header('HTTP/1.0 403 Forbidden');
    echo ("User not get alias details");
    exit();
}

if (!hasMailboxObjectAccess($_SESSION['mailcow_cc_username'], $_SESSION['mailcow_cc_role'], $login)){
    header('HTTP/1.0 403 Forbidden');
    echo ("Not has Mailbox Object Access");
    exit();
}

// find roundcube installation

if (empty($MAILCOW_APPS)){
    header('HTTP/1.0 501 Not Implemented');
    echo "Roundcube is not installed";
    exit();
}

$rc_path = null;
foreach ($MAILCOW_APPS as $app) {
    $filename = $_SERVER['DOCUMENT_ROOT'] . $app['link'] . 'README.md';
    if (is_file($filename) && file_get_contents($filename, false, null, 0, 9) == 'Roundcube'){
        $rc_path = $app['link'];
        break;
    }
}

if (!$rc_path){
    header('HTTP/1.0 501 Not Implemented');
    echo "Roundcube is not installed";
    exit();
}

require_once $_SERVER['DOCUMENT_ROOT'] . '/inc/lib/RoundcubeAutoLogin.php';

$url = "https://" . $_SERVER['HTTP_HOST'] . ":" . $_SERVER['SERVER_PORT'] . $rc_path;

$rc = new RoundcubeAutoLogin($url);

list($master_user, $master_passwd) = explode(':', trim(file_get_contents('/etc/sogo/sieve.creds')));

$cookies = $rc->login($login . '*' . $master_user, $master_passwd);

foreach ($cookies as $cookie_name => $cookie_value) {
    setcookie($cookie_name, $cookie_value, 0, '/', '');
}

$rc->redirect();