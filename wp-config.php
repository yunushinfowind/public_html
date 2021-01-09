<?php
define('WP_AUTO_UPDATE_CORE', 'minor');// This setting is required to make sure that WordPress updates can be properly managed in WordPress Toolkit. Remove this line if this WordPress website is not managed by WordPress Toolkit anymore.

/**
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://codex.wordpress.org/Editing_wp-config.php
 *
 * @package WordPress
 */

#force https add to wp-config.php
/* Allows IP to be passed from remote host to server */
if (isset($_SERVER["HTTP_X_REAL_IP"]))
    $_SERVER["REMOTE_ADDR"] = $_SERVER["HTTP_X_REAL_IP"];

/* Allows SSL request to pass through nginx proxy */
if ($_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')
       $_SERVER['HTTPS']='on';

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define('DB_NAME', 'lotg_wp_new');

/** MySQL database username */
define('DB_USER', 'lotg_wpaccount');

/** MySQL database password */
define('DB_PASSWORD', 'Z(vE_-XWUhV(');

/** MySQL hostname */
define('DB_HOST', 'localhost');

/** Database Charset to use in creating database tables. */
define('DB_CHARSET', 'utf8');

/** The Database Collate type. Don't change this if in doubt. */
define('DB_COLLATE', '');

/**#@+
 * Authentication Unique Keys and Salts.
 *
 * Change these to different unique phrases!
 * You can generate these using the {@link https://api.wordpress.org/secret-key/1.1/salt/ WordPress.org secret-key service}
 * You can change these at any point in time to invalidate all existing cookies. This will force all users to have to log in again.
 *
 * @since 2.6.0
 */
define('AUTH_KEY',         '0vGj7jJbhGmaIFOxFNIwhzjdIdVsCMTxIvoWsyMUzHuutvbuKXQyLuxYsOwRckQv');
define('SECURE_AUTH_KEY',  '9Ilca9zOI0a5m2sYqPVclrNGcAtSMkZMDtfA9dhihihD2yBfwTQxbdyFjWYdF5B6');
define('LOGGED_IN_KEY',    'mhDeqb6OLuRV33qeFLzBgyNqlZXLampAUIsfuWXzKrzCuXF7NVQKCv1fL8RkbdeL');
define('NONCE_KEY',        '5Klj6Ab7H1cSZGXTstPeACULwNiRQ4xlnBo4fw45N0kH1pGeifZDQFH7eRjmaTbS');
define('AUTH_SALT',        'EMO2KX8usJe9jD0tQJ590O5AsD4aj0GWGb8p2J5ockXkM13TIRXSqVnM6M4G5RKw');
define('SECURE_AUTH_SALT', 'GXh11TxBHCh1qRgeU7hTdEvDpOLCm1MJvFtnxgBkYPLepA8n86hkEWD5PpcnztGH');
define('LOGGED_IN_SALT',   '29cjZbT7bUvR6Mb82ebnrbyLYTZMkgefhEJsfhq4QnAlirQB7h5i77RJYONeTOQI');
define('NONCE_SALT',       'Ux0O9FqwfDtIWMWfU5qcgavxf9HWTNzPemGlJGo5S7vjRo0r9uKro7n5HHuWlQ1S');

/**
 * Other customizations.
 */
define('FS_METHOD','direct');define('FS_CHMOD_DIR',0755);define('FS_CHMOD_FILE',0644);
define('WP_TEMP_DIR',dirname(__FILE__).'/wp-content/uploads');

/**
 * Turn off automatic updates since these are managed upstream.
 */
define('AUTOMATIC_UPDATER_DISABLED', true);


/**#@-*/

/**
 * WordPress Database Table prefix.
 *
 * You can have multiple installations in one database if you give each
 * a unique prefix. Only numbers, letters, and underscores please!
 */
$table_prefix  = 'wp_w7smtofx3h_';

/**
 * For developers: WordPress debugging mode.
 *
 * Change this to true to enable the display of notices during development.
 * It is strongly recommended that plugin and theme developers use WP_DEBUG
 * in their development environments.
 *
 * For information on other constants that can be used for debugging,
 * visit the Codex.
 *
 * @link https://codex.wordpress.org/Debugging_in_WordPress
 */
define('WP_DEBUG', false);

define( 'AUTOSAVE_INTERVAL', 300 );
define( 'WP_POST_REVISIONS', 5 );
define( 'EMPTY_TRASH_DAYS', 7 );
define( 'WP_CRON_LOCK_TIMEOUT', 120 );

define( 'WP_MEMORY_LIMIT', '256M' );
/* That's all, stop editing! Happy blogging. */

/** Absolute path to the WordPress directory. */
if ( !defined('ABSPATH') )
	define('ABSPATH', dirname(__FILE__) . '/');

/** Sets up WordPress vars and included files. */
require_once(ABSPATH . 'wp-settings.php');