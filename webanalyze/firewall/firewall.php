<?php
/**
 * Collect all request module
 * Copyright by SiteGuarding.com
 * Date: 19 Oct 2015
 * ver.: 2.1
 */
define( 'SITEGUARDING_DEBUG', false);
define( 'SITEGUARDING_DEBUG_IP', '1.2.3.4');

if (isset($_REQUEST['task']) && $_REQUEST['task'] == 'cron' && isset($_REQUEST['access_key']) && isset($_REQUEST['anticache'])) return;

if( ! ini_get('date.timezone') )
{
    date_default_timezone_set('GMT');
}


if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') $DIRSEP = '\\';
else $DIRSEP = '/';

$file_firewall_class = dirname(__FILE__).$DIRSEP.'firewall.class.php';
$file_firewall_config = dirname(__FILE__).$DIRSEP.'firewall.config.php';
$file_firewall_rules = dirname(__FILE__).$DIRSEP.'rules.txt';

/**
 * Debug some values
 */
if (SITEGUARDING_DEBUG === true && $_SERVER["REMOTE_ADDR"] == SITEGUARDING_DEBUG_IP)
{
    echo 'Class '.$file_firewall_class."<br>";
    echo 'Config '.$file_firewall_config."<br>";
    echo 'Rules '.$file_firewall_rules."<br>";
    echo 'Request: <br><pre>'.print_r($_REQUEST, true).'</pre>'."<br><br>";
    echo 'Server: <br><pre>'.print_r($_SERVER, true).'</pre>'."<br><br>";
}


if (file_exists($file_firewall_class)) include_once($file_firewall_class);
else die('File is not loaded: '.$file_firewall_class);


if (file_exists($file_firewall_config)) include_once($file_firewall_config);
else die('File is not loaded: '.$file_firewall_config);

if (!file_exists($file_firewall_rules)) die('File is not loaded: rules.txt');

if (SITEGUARDING_FIREWALL_STATUS === false) return;     // exit if firewall is disabled


$firewall = new SiteGuarding_Firewall();

$firewall->this_session_rule = SITEGUARDING_DEFAULT_ACTION;
$firewall->email_for_alerts = SITEGUARDING_EMAIL_FOR_ALERTS;
$firewall->save_empty_requests = SITEGUARDING_SAVE_EMPTY_REQUESTS;
$firewall->single_log_file = SITEGUARDING_SINGLE_LOG_FILE;
$firewall->scan_path = SITEGUARDING_SCAN_PATH;
$firewall->dirsep = SITEGUARDING_DIRSEP;
$firewall->float_file_folder = SITEGUARDING_FLOAT_FILE_FOLDER;

// Check php.ini in all the folders
//$firewall->InstallPHPini();




if (!$firewall->LoadRules()) die('Rules are not loaded');



// Load and parse the rules
$firewall->LogRequest();

// Checking this request based on the rules
if ($firewall->CheckIP_in_Allowed($_SERVER["REMOTE_ADDR"])) return;

if ($firewall->CheckIP_in_Alert($_SERVER["REMOTE_ADDR"]))
{   // Send alert to admin
    $subject = 'Access from IP '.$_SERVER["REMOTE_ADDR"];
    $message = date("Y-m-d H:i:s")."\n".
    	"IP:".$_SERVER["REMOTE_ADDR"]."\n".
    	"Link:"."http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"."\n".
    	"File:".$_SERVER[SCRIPT_FILENAME]."\n".
    	print_r($_REQUEST, true)."\n\n";
    $firewall->SendEmail($subject, $message);
}

if ($firewall->CheckIP_in_Blocked($_SERVER["REMOTE_ADDR"]))
{
    $firewall->Block_This_Session('Not allowed IP '.$_SERVER["REMOTE_ADDR"]);
    $firewall->LogRequest(true);
    exit;
}

// Global RULES
$tmp_session_rule = $firewall->Session_Apply_Rules($_SERVER['SCRIPT_FILENAME']);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Rules for the file');
    $firewall->LogRequest(true);
    exit;
}


// BLOCK_RULES_IP
$tmp_session_rule = $firewall->Session_Apply_BLOCK_RULES_IP($_SERVER['SCRIPT_FILENAME'], $_SERVER["REMOTE_ADDR"]);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Rules for the file & IP');
    $firewall->LogRequest(true);
    exit;
}


// Check Requests
$tmp_session_rule = $firewall->Session_Check_Requests($_REQUEST);
if ($tmp_session_rule != '') $firewall->this_session_rule = $tmp_session_rule;

if ($firewall->this_session_rule == 'block')
{
    $firewall->Block_This_Session('Request rule => '.$firewall->this_session_reason_to_block, true);
    $firewall->LogRequest(true);
    exit;
}

if (SITEGUARDING_DEBUG === true && $_SERVER["REMOTE_ADDR"] == SITEGUARDING_DEBUG_IP)
{
    echo 'Finished'."<br>";
}


?>