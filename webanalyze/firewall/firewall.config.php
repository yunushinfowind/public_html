<?php
define( 'SITEGUARDING_SCAN_PATH', '/home/content/p3pnexwpnas07_data01/45/2597545/html/');		  // Full path e.g. /home/aaa/public_html/
define( 'SITEGUARDING_DIRSEP', '/');		                          // for Unix leave /

define( 'SITEGUARDING_DEFAULT_ACTION', 'allow');		// Defaut action for session
define( 'SITEGUARDING_EMAIL_FOR_ALERTS', 'team@siteguarding.com');		// Email for alerts
define( 'SITEGUARDING_SINGLE_LOG_FILE', false);		// false - For each file creates own log file, false - single log file
define( 'SITEGUARDING_SAVE_EMPTY_REQUESTS', true);	// true - save all requests (if (count($_REQUEST) =>0)
define( 'SITEGUARDING_FLOAT_FILE_FOLDER', false);	// true - for global server analyze, false for single website
?>