<?php
/**
 * Version 2.6
 * Date: 23 Sep 2015
 * 
 * SiteGuarding.com Antivirus 
 */
include("antivirus_config.php");
 
define('SCRIPT_VERSION', '2.6');
define('ANTIVIRUS_PLATFORM', 'any');
define('ANTIVIRUS_CMS', 'any');

define('SITEGUARDING_SERVER', 'http://www.siteguarding.com/ext/antivirus/index.php');
define('SITEGUARDING_SERVER_IP_1', '185.72.156.128');
define('SITEGUARDING_SERVER_IP_2', '185.72.156.129');

define('DEBUG_FLAG', true);
define('DEBUG_FILELIST', false);
define('CALLBACK_PACK_FILE', false);


// Init
set_time_limit ( 7200 );    // 1 hour
ignore_user_abort(true);
error_reporting( 0 );
ini_set('error_log',NULL);
ini_set('log_errors',0);
ini_set('max_execution_time',7200);
ini_set('post_max_size', '256M');
ini_set('upload_max_filesize', '256M');
ini_set('memory_limit', '512M');

$scan_path = dirname(__FILE__);
if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') 
{	// Windows
	define('DIRSEP', '\\');
	$scan_path = str_replace(DIRSEP."webanalyze", DIRSEP, $scan_path);
    $scan_path = $scan_path.DIRSEP;
}
else {
	// Unix
	define('DIRSEP', '/');
	$scan_path = substr( $scan_path, 1, strrpos($scan_path, DIRSEP) );
    $scan_path = DIRSEP.$scan_path;
}
$scan_path = str_replace( DIRSEP.DIRSEP, DIRSEP, $scan_path );
define('SCAN_PATH', $scan_path);


// Commands
$task = trim($_REQUEST['task']);
$access_key = trim($_REQUEST['access_key']);

if ($access_key != ACCESS_KEY) {PrintResultOutput('Wrong Access Key', false);exit;}


// Check server settings
$result = checkServerSettings(true);
if (count($result) > 0 || $result === false)
{
	PrintResultOutput($result, false);	
}


// Execute tasks
switch ($task)
{
	// */webanalyze/antivirus.php?task=status&access_key=e5d5ccd60d9e59204466c5adace6093f&answer=xxx
	case 'status':
		$status_data = GetStatus();
		PrintResultOutput($status_data, true);	
		break;
	
	// */webanalyze/antivirus.php?task=scan&access_key=e43c132d47dd6c5013b19a0f7fa83f25&session_report_key=xxxx&email=support@safetybis.com
	case 'scan':
		scan();
		break;
		
	// */webanalyze/antivirus.php?task=scan_status&access_key=e43c132d47dd6c5013b19a0f7fa83f25
	case 'scan_status':
		echo readProgress();
		break;
		
	// */webanalyze/antivirus.php?task=upgrade&access_key=e43c132d47dd6c5013b19a0f7fa83f25
	case 'upgrade':
		$result = ScriptUpgrade();
		PrintResultOutput($result['txt'], $result['status']);	
		break;
		
	// */webanalyze/antivirus.php?task=get_malware_files&access_key=e43c132d47dd6c5013b19a0f7fa83f25
	case 'get_malware_files':
		$result = get_malware_files();
		echo $result;	
		break;
		
	default:
		PrintResultOutput('Wrong Task', false);	
}
exit;

/**
 * Functions
 */
 


function scan()
{
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') define(DIRSEP, '\\');
	else define(DIRSEP, '/');
    

    $domain = GetDomain();
    $access_key = ACCESS_KEY;
    $license_info = GetLicenseInfo($domain, $access_key);    
        
        
    $scanner = new SGAntiVirus_scanner();
    
    $scanner->antivirus_version = SCRIPT_VERSION;
    $scanner->antivirus_platform = ANTIVIRUS_PLATFORM;
    $scanner->antivirus_cms = ANTIVIRUS_CMS;
    
    $scanner->work_dir = dirname(__FILE__).DIRSEP;
    $scanner->tmp_dir = dirname(__FILE__).DIRSEP;
    $scanner->membership = $license_info['membership'];
    $scanner->scan_path = SCAN_PATH;
    $scanner->access_key = ACCESS_KEY;
    $scanner->domain = $domain;
    $scanner->email = trim($_REQUEST['email']);
    $scanner->session_report_key = trim($_REQUEST['session_report_key']);
    
    
    $scanner->scanner();
}





function readProgress()
{
	$a = array('txt' => 'Loading...', 'progress' => 0);
	
	// Read log file
	$filename = dirname(__FILE__)."/antivirus_last_action.log";
	$handle = fopen($filename, "r");
	if ($handle === false) return $a['progress']."|".$a['txt'];
	$contents = fread($handle, filesize($filename));
	fclose($handle);
	
	$contents = json_decode($contents, true);
	if ($contents == NULL || $contents === false) return $a['progress']."|".$a['txt'];
	
	$a['txt'] = trim($contents['txt']);
	$a['progress'] = floatval($contents['progress']);
	
	$val = $a['progress'];
	$new_val = round($val+0.1 , 2);
	if ($new_val > 100) $new_val = 90;
	$val_txt = trim($a['txt']);
	
	$a = array(
		'txt' => $val_txt,
		'progress' => $new_val
	);
	

	$filename = dirname(__FILE__)."/antivirus_last_action.log";
	$fp = fopen($filename, 'w');
	fwrite($fp, json_encode($a));
	fclose($fp);
	
	$ret_value = $val."|".$val_txt;
	
	if (file_exists(dirname(__FILE__).DIRSEP.'flag_terminated.tmp'))
	{
		$ret_value = 'report_redirect';
	}
	
	return $ret_value;
}



function GetDomain()
{
	global $_SERVER;
	
	$domain = $_SERVER['SERVER_NAME'];
    //$domain = str_replace("www.", "", $domain);
    
	return "http://".$domain;	
}


function checkServerSettings($return_error_names = false)
{
	$error_name = array();
	$error = 0;
	
	// Check tmp folder is writable
    if (strtoupper(substr(PHP_OS, 0, 3)) !== 'WIN')
    { 
    	if (!is_writable(dirname(__FILE__)))
    	{
    		chmod ( dirname(__FILE__).'/' , 0777 ); 
    		if (!is_writable(dirname(__FILE__).'/'))
    		{
    			$error = 1;
    			$error_name[] = 'tmp is not writable';
    		}
    	}
    }
	
	
	if ($return_error_names) return $error_name;
	if ($error == 1) return false;
	else return true;
}

function ScriptUpgrade()
{
    global $_SERVER;

    if ($_SERVER['REMOTE_ADDR'] != SITEGUARDING_SERVER_IP_1 && $_SERVER['REMOTE_ADDR'] != SITEGUARDING_SERVER_IP_2)
    {
    	$a = array('txt' => 'wrong siteguarding.com server IP: '.$_SERVER['REMOTE_ADDR'].' '.SITEGUARDING_SERVER_IP_1.' '.SITEGUARDING_SERVER_IP_2, 'status' => false);
    	return $a;
    }

	$destination = __FILE__;
	
	$url = 'http://www.siteguarding.com/_get_file.php?file=antivirus&time='.time();
	
	$status = CreateRemote_file_contents($url, $destination);

	if ($status) $a = array('txt' => 'updated', 'status' => true);
	else $a = array('txt' => 'cant move/save uploaded file', 'status' => false);
	
	return $a;
}


function CreateRemote_file_contents($url, $dst)
{
    if (extension_loaded('curl')) 
    {
        $dst = fopen($dst, 'w');
        
        $ch = curl_init();
        
        curl_setopt($ch, CURLOPT_URL, $url );
        curl_setopt($ch, CURLOPT_USERAGENT, "Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)");
        curl_setopt($ch, CURLOPT_TIMEOUT, 3600);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, 3600000);
        curl_setopt($ch, CURLOPT_FILE, $dst);
        curl_setopt($ch, CURLOPT_FAILONERROR, true);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10); // 10 sec
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, 10000); // 10 sec
        curl_setopt($ch, CURLOPT_BINARYTRANSFER, 1);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        
        $a = curl_exec($ch);
        if ($a === false)  return false;
        
        $info = curl_getinfo($ch);
        
        curl_close($ch);
        fflush($dst);
        fclose($dst);
        
        return $info['size_download'];
    }
    else return false;
}



function GetStatus()
{
	$a = array( 
		'answer' => md5(trim($_REQUEST['answer'])),
		'version' => SCRIPT_VERSION,
		'md5' => md5_file(__FILE__),
		'debug' => ReadDebug()
	);
	return $a;
} 


function PrintResultOutput($msg, $type = false) // false = error, true - ok
{
    if ($type)
    {
        // Success
        if (is_array($msg))
        {
        	$a = $msg;
			$a['status'] = 'ok';
        }
        else {
        	$a = array(
            	'status' => 'ok',
            	'msg' => $msg
        	);
       	}
    } 
    else {
        // Error
        if (is_array($msg))
        {
        	$a = $msg;
			$a['status'] = 'error';
        }
        else {
        	$a = array(
            	'status' => 'error',
            	'msg' => $msg
        	);
       	}
    }
    
    echo json_encode($a);
}




function GetLicenseInfo($domain, $access_key)
{
	$link = SITEGUARDING_SERVER.'?action=licenseinfo&type=json&data=';
	
    $data = array(
		'domain' => $domain,
		'access_key' => $access_key,
		'product_type' => 'any'
	);
    $link .= base64_encode(json_encode($data));
    
    $postdata = array();
    
	$opts = array(
	  'http'=>array(
	    'method'=>"GET",
	    'header'=>"Accept-language: en\r\n"
	  )
	);
	$context  = stream_context_create($opts);
	$msg = file_get_contents($link);
	
    $msg = trim($msg);
    if ($msg == '') return false;
    
    return (array)json_decode($msg, true);
}
	


function get_malware_files()
{
	error_reporting(0);

	$domain = GetDomain();
			
	$license_info = GetLicenseInfo($domain, ACCESS_KEY);


	if (intval($_GET['showcontent']) == 1)
	{
		ShowFilesForAnalyze($license_info['last_scan_files']);
		exit;
	}
	

	$a = SendFilesForAnalyze( $license_info['last_scan_files'], $license_info['email'] );
	if ($a === true)
	{
		$tmp_txt = 'Files sent for analyze. You will get report by email '.$license_info['email'].' Files:'.print_r( $license_info['last_scan_files'],true);
		
		$result_txt = array(
			'status' => 'OK',
			'description' => $tmp_txt
		);
		DebugLog($tmp_txt);
	}
	else {
		$tmp_txt = 'Operation is failed. Nothing sent for analyze. Files:'.print_r( $license_info['last_scan_files'],true);
		
		$result_txt = array(
			'status' => 'ERROR',
			'description' => $tmp_txt
		);
		DebugLog($tmp_txt);
	}
	
	return json_encode($result_txt);
}


function SendFilesForAnalyze($files_array = array(), $email_from)
{
	$result = false;
	$files = array();
	
	$domain = GetDomain();
	
	if (count($files_array['main']))
	{
		foreach ($files_array['main'] as $k => $filename)
		{
			$files[$filename] = $filename;	
		}
	}
	if (count($files_array['heuristic']))
	{
		foreach ($files_array['heuristic'] as $k => $filename)
		{
			$files[$filename] = $filename;	
		}
	}
	sort($files);
	
	
	if (count($files))
	{
		$separator = md5(time());
		$eol = PHP_EOL;
		
		// main header (multipart mandatory)
		$headers = "From: ".$domain." <".$email_from.">" . $eol;
		$headers .= "MIME-Version: 1.0" . $eol;
		$headers .= "Content-Type: multipart/mixed; boundary=\"" . $separator . "\"" . $eol . $eol;
		$headers .= "Content-Transfer-Encoding: 7bit" . $eol;
		$headers .= "This is a MIME encoded message." . $eol . $eol;
		
		// message
		$message = 'Files for review. Domain: '.$domain."\n\n".print_r($files, true);
		$headers .= "--" . $separator . $eol;
		$headers .= "Content-Type: text/plain; charset=\"iso-8859-1\"" . $eol;
		$headers .= "Content-Transfer-Encoding: 8bit" . $eol . $eol;
		$headers .= $message . $eol . $eol;
		
		
		// attachment
		foreach ($files as $file)
		{
			$filename = basename($file);
			$file_full_path = SCAN_PATH.'/'.$file;
			$file_size = filesize($file_full_path);
			$handle = fopen($file_full_path, "r");
			$content = fread($handle, $file_size);
			fclose($handle);
			$content = chunk_split(base64_encode($content));
			
			$headers .= "--" . $separator . $eol;
			$headers .= "Content-Type: application/octet-stream; name=\"" . $filename . "\"" . $eol;
			$headers .= 'Content-Description: ' . $file. $eol;
			$headers .= "Content-Transfer-Encoding: base64" . $eol;
			$headers .= 'Content-Disposition: attachment filename="' . $filename . '"; size=' . $file_size.  ';' . $eol . $eol;
			$headers .= $content . $eol . $eol;
		}
		
		$headers .= "--" . $separator . "--". $eol;
		
		//Send Mail
		$subject = 'Antivirus Files Review ('.$domain.')';
		$mailto = 'review@siteguarding.com';
		$result = mail($mailto, $subject, "", $headers);
	}
	
	
	return $result;
}


function ShowFilesForAnalyze($files_array = array())
{
	$files = array();
	
	if (count($files_array['main']))
	{
		foreach ($files_array['main'] as $k => $filename)
		{
			$files[$filename] = $filename;	
		}
	}
	if (count($files_array['heuristic']))
	{
		foreach ($files_array['heuristic'] as $k => $filename)
		{
			$files[$filename] = $filename;	
		}
	}
	
	sort($files);
	
	echo '<pre>';
	print_r($files);
	echo '</pre>';
	
	echo '<br><br>';
	
	if (count($files))
	{
		foreach ($files as $file)
		{
			$file_full_path = SCAN_PATH.'/'.$file;
			echo $file_full_path.' Filesize: '.filesize($file_full_path).' bytes<br><br>';
			$handle = fopen($file_full_path, "r");
			$content =  fread($handle, filesize($file_full_path));
			echo 'Content: <pre>'.$content.'</pre>';
			fclose($handle);
			
			echo '<br><br><hr><br><br>';
		}
	}
	
	
}




function ReadDebug()
{
	// Read debug file
	$filename = dirname(__FILE__).DIRSEP."debug.log";
	$handle = fopen($filename, "r");
	if ($handle === false) return '';
	$contents = fread($handle, filesize($filename));
	fclose($handle);
	
	return $contents;
}


function DebugLog($txt, $clean_log_file = false)
{
	if ($clean_log_file) $fp = fopen(dirname(__FILE__).DIRSEP.'debug.log', 'w');
	else $fp = fopen(dirname(__FILE__).DIRSEP.'debug.log', 'a');
	$a = date("Y-m-d H:i:s")." ".$txt."\n";
	fwrite($fp, $a);
	fclose($fp);
}



/**
 * Extra classes
 */


class Zip {
    const VERSION = 1.62;

    const ZIP_LOCAL_FILE_HEADER = "\x50\x4b\x03\x04"; // Local file header signature
    const ZIP_CENTRAL_FILE_HEADER = "\x50\x4b\x01\x02"; // Central file header signature
    const ZIP_END_OF_CENTRAL_DIRECTORY = "\x50\x4b\x05\x06\x00\x00\x00\x00"; //end of Central directory record

    const EXT_FILE_ATTR_DIR = 010173200020;  // Permission 755 drwxr-xr-x = (((S_IFDIR | 0755) << 16) | S_DOS_D);
    const EXT_FILE_ATTR_FILE = 020151000040; // Permission 644 -rw-r--r-- = (((S_IFREG | 0644) << 16) | S_DOS_A);

    const ATTR_VERSION_TO_EXTRACT = "\x14\x00"; // Version needed to extract
    const ATTR_MADE_BY_VERSION = "\x1E\x03"; // Made By Version

	// UID 1000, GID 0
	const EXTRA_FIELD_NEW_UNIX_GUID = "\x75\x78\x0B\x00\x01\x04\xE8\x03\x00\x00\x04\x00\x00\x00\x00";

	// Unix file types
	const S_IFIFO  = 0010000; // named pipe (fifo)
	const S_IFCHR  = 0020000; // character special
	const S_IFDIR  = 0040000; // directory
	const S_IFBLK  = 0060000; // block special
	const S_IFREG  = 0100000; // regular
	const S_IFLNK  = 0120000; // symbolic link
	const S_IFSOCK = 0140000; // socket

	// setuid/setgid/sticky bits, the same as for chmod:

	const S_ISUID  = 0004000; // set user id on execution
	const S_ISGID  = 0002000; // set group id on execution
	const S_ISTXT  = 0001000; // sticky bit

	// And of course, the other 12 bits are for the permissions, the same as for chmod:
	// When addding these up, you can also just write the permissions as a simgle octal number
	// ie. 0755. The leading 0 specifies octal notation.
	const S_IRWXU  = 0000700; // RWX mask for owner
	const S_IRUSR  = 0000400; // R for owner
	const S_IWUSR  = 0000200; // W for owner
	const S_IXUSR  = 0000100; // X for owner
	const S_IRWXG  = 0000070; // RWX mask for group
	const S_IRGRP  = 0000040; // R for group
	const S_IWGRP  = 0000020; // W for group
	const S_IXGRP  = 0000010; // X for group
	const S_IRWXO  = 0000007; // RWX mask for other
	const S_IROTH  = 0000004; // R for other
	const S_IWOTH  = 0000002; // W for other
	const S_IXOTH  = 0000001; // X for other
	const S_ISVTX  = 0001000; // save swapped text even after use

	// Filetype, sticky and permissions are added up, and shifted 16 bits left BEFORE adding the DOS flags.

	// DOS file type flags, we really only use the S_DOS_D flag.

	const S_DOS_A  = 0000040; // DOS flag for Archive
	const S_DOS_D  = 0000020; // DOS flag for Directory
	const S_DOS_V  = 0000010; // DOS flag for Volume
	const S_DOS_S  = 0000004; // DOS flag for System
	const S_DOS_H  = 0000002; // DOS flag for Hidden
	const S_DOS_R  = 0000001; // DOS flag for Read Only

    private $zipMemoryThreshold = 1048576; // Autocreate tempfile if the zip data exceeds 1048576 bytes (1 MB)

    private $zipData = NULL;
    private $zipFile = NULL;
    private $zipComment = NULL;
    private $cdRec = array(); // central directory
    private $offset = 0;
    private $isFinalized = FALSE;
    private $addExtraField = TRUE;

    private $streamChunkSize = 65536;
    private $streamFilePath = NULL;
    private $streamTimestamp = NULL;
    private $streamFileComment = NULL;
    private $streamFile = NULL;
    private $streamData = NULL;
    private $streamFileLength = 0;
	private $streamExtFileAttr = null;
	/**
	 * A custom temporary folder, or a callable that returns a custom temporary file.
	 * @var string|callable
	 */
	public static $temp = null;

    /**
     * Constructor.
     *
     * @param boolean $useZipFile Write temp zip data to tempFile? Default FALSE
     */
    function __construct($useZipFile = FALSE) {
        if ($useZipFile) {
            $this->zipFile = tmpfile();
        } else {
            $this->zipData = "";
        }
    }

    function __destruct() {
        if (is_resource($this->zipFile)) {
            fclose($this->zipFile);
        }
        $this->zipData = NULL;
    }

    /**
     * Extra fields on the Zip directory records are Unix time codes needed for compatibility on the default Mac zip archive tool.
     * These are enabled as default, as they do no harm elsewhere and only add 26 bytes per file added.
     *
     * @param bool $setExtraField TRUE (default) will enable adding of extra fields, anything else will disable it.
     */
    function setExtraField($setExtraField = TRUE) {
        $this->addExtraField = ($setExtraField === TRUE);
    }

    /**
     * Set Zip archive comment.
     *
     * @param string $newComment New comment. NULL to clear.
     * @return bool $success
     */
    public function setComment($newComment = NULL) {
        if ($this->isFinalized) {
            return FALSE;
        }
        $this->zipComment = $newComment;

        return TRUE;
    }

    /**
     * Set zip file to write zip data to.
     * This will cause all present and future data written to this class to be written to this file.
     * This can be used at any time, even after the Zip Archive have been finalized. Any previous file will be closed.
     * Warning: If the given file already exists, it will be overwritten.
     *
     * @param string $fileName
     * @return bool $success
     */
    public function setZipFile($fileName) {
        if (is_file($fileName)) {
            unlink($fileName);
        }
        $fd=fopen($fileName, "x+b");
        if (is_resource($this->zipFile)) {
            rewind($this->zipFile);
            while (!feof($this->zipFile)) {
                fwrite($fd, fread($this->zipFile, $this->streamChunkSize));
            }

            fclose($this->zipFile);
        } else {
            fwrite($fd, $this->zipData);
            $this->zipData = NULL;
        }
        $this->zipFile = $fd;

        return TRUE;
    }

    /**
     * Add an empty directory entry to the zip archive.
     * Basically this is only used if an empty directory is added.
     *
     * @param string $directoryPath Directory Path and name to be added to the archive.
     * @param int    $timestamp     (Optional) Timestamp for the added directory, if omitted or set to 0, the current time will be used.
     * @param string $fileComment   (Optional) Comment to be added to the archive for this directory. To use fileComment, timestamp must be given.
	 * @param int    $extFileAttr   (Optional) The external file reference, use generateExtAttr to generate this.
     * @return bool $success
     */
    public function addDirectory($directoryPath, $timestamp = 0, $fileComment = NULL, $extFileAttr = self::EXT_FILE_ATTR_DIR) {
        if ($this->isFinalized) {
            return FALSE;
        }
        $directoryPath = str_replace("\\", "/", $directoryPath);
        $directoryPath = rtrim($directoryPath, "/");

        if (strlen($directoryPath) > 0) {
            $this->buildZipEntry($directoryPath.'/', $fileComment, "\x00\x00", "\x00\x00", $timestamp, "\x00\x00\x00\x00", 0, 0, $extFileAttr);
            return TRUE;
        }
        return FALSE;
    }

    /**
     * Add a file to the archive at the specified location and file name.
     *
     * @param string $data        File data.
     * @param string $filePath    Filepath and name to be used in the archive.
     * @param int    $timestamp   (Optional) Timestamp for the added file, if omitted or set to 0, the current time will be used.
     * @param string $fileComment (Optional) Comment to be added to the archive for this file. To use fileComment, timestamp must be given.
     * @param bool   $compress    (Optional) Compress file, if set to FALSE the file will only be stored. Default TRUE.
	 * @param int    $extFileAttr (Optional) The external file reference, use generateExtAttr to generate this.
     * @return bool $success
     */
    public function addFile($data, $filePath, $timestamp = 0, $fileComment = NULL, $compress = TRUE, $extFileAttr = self::EXT_FILE_ATTR_FILE) {
        if ($this->isFinalized) {
            return FALSE;
        }

        if (is_resource($data) && get_resource_type($data) == "stream") {
            $this->addLargeFile($data, $filePath, $timestamp, $fileComment, $extFileAttr);
            return FALSE;
        }

        $gzData = "";
        $gzType = "\x08\x00"; // Compression type 8 = deflate
        $gpFlags = "\x00\x00"; // General Purpose bit flags for compression type 8 it is: 0=Normal, 1=Maximum, 2=Fast, 3=super fast compression.
        $dataLength = strlen($data);
        $fileCRC32 = pack("V", crc32($data));

        if ($compress) {
            $gzTmp = gzcompress($data);
            $gzData = substr(substr($gzTmp, 0, strlen($gzTmp) - 4), 2); // gzcompress adds a 2 byte header and 4 byte CRC we can't use.
            // The 2 byte header does contain useful data, though in this case the 2 parameters we'd be interrested in will always be 8 for compression type, and 2 for General purpose flag.
            $gzLength = strlen($gzData);
        } else {
            $gzLength = $dataLength;
        }

        if ($gzLength >= $dataLength) {
            $gzLength = $dataLength;
            $gzData = $data;
            $gzType = "\x00\x00"; // Compression type 0 = stored
            $gpFlags = "\x00\x00"; // Compression type 0 = stored
        }

        if (!is_resource($this->zipFile) && ($this->offset + $gzLength) > $this->zipMemoryThreshold) {
            $this->zipflush();
        }

        $this->buildZipEntry($filePath, $fileComment, $gpFlags, $gzType, $timestamp, $fileCRC32, $gzLength, $dataLength, $extFileAttr);

        $this->zipwrite($gzData);

        return TRUE;
    }

    /**
     * Add the content to a directory.
     *
     * @author Adam Schmalhofer <Adam.Schmalhofer@gmx.de>
     * @author A. Grandt
     *
     * @param string $realPath       Path on the file system.
     * @param string $zipPath        Filepath and name to be used in the archive.
     * @param bool   $recursive      Add content recursively, default is TRUE.
     * @param bool   $followSymlinks Follow and add symbolic links, if they are accessible, default is TRUE.
     * @param array &$addedFiles     Reference to the added files, this is used to prevent duplicates, efault is an empty array.
     *                               If you start the function by parsing an array, the array will be populated with the realPath
     *                               and zipPath kay/value pairs added to the archive by the function.
	 * @param bool   $overrideFilePermissions Force the use of the file/dir permissions set in the $extDirAttr
	 *							     and $extFileAttr parameters.
	 * @param int    $extDirAttr     Permissions for directories.
	 * @param int    $extFileAttr    Permissions for files.
     */
    public function addDirectoryContent($realPath, $zipPath, $recursive = TRUE, $followSymlinks = TRUE, &$addedFiles = array(),
					$overrideFilePermissions = FALSE, $extDirAttr = self::EXT_FILE_ATTR_DIR, $extFileAttr = self::EXT_FILE_ATTR_FILE) {
        if (file_exists($realPath) && !isset($addedFiles[realpath($realPath)])) {
            if (is_dir($realPath)) {
				if ($overrideFilePermissions) {
	                $this->addDirectory($zipPath, 0, null, $extDirAttr);
				} else {
					$this->addDirectory($zipPath, 0, null, self::getFileExtAttr($realPath));
				}
            }

            $addedFiles[realpath($realPath)] = $zipPath;

            $iter = new DirectoryIterator($realPath);
            foreach ($iter as $file) {
                if ($file->isDot()) {
                    continue;
                }
                $newRealPath = $file->getPathname();
                $newZipPath = self::pathJoin($zipPath, $file->getFilename());

                if (file_exists($newRealPath) && ($followSymlinks === TRUE || !is_link($newRealPath))) {
                    if ($file->isFile()) {
                        $addedFiles[realpath($newRealPath)] = $newZipPath;
						if ($overrideFilePermissions) {
							$this->addLargeFile($newRealPath, $newZipPath, 0, null, $extFileAttr);
						} else {
							$this->addLargeFile($newRealPath, $newZipPath, 0, null, self::getFileExtAttr($newRealPath));
						}
                    } else if ($recursive === TRUE) {
                        $this->addDirectoryContent($newRealPath, $newZipPath, $recursive, $followSymlinks, $addedFiles, $overrideFilePermissions, $extDirAttr, $extFileAttr);
                    } else {
						if ($overrideFilePermissions) {
							$this->addDirectory($zipPath, 0, null, $extDirAttr);
						} else {
							$this->addDirectory($zipPath, 0, null, self::getFileExtAttr($newRealPath));
						}
                    }
                }
            }
        }
    }

    /**
     * Add a file to the archive at the specified location and file name.
     *
     * @param string $dataFile    File name/path.
     * @param string $filePath    Filepath and name to be used in the archive.
     * @param int    $timestamp   (Optional) Timestamp for the added file, if omitted or set to 0, the current time will be used.
     * @param string $fileComment (Optional) Comment to be added to the archive for this file. To use fileComment, timestamp must be given.
	 * @param int    $extFileAttr (Optional) The external file reference, use generateExtAttr to generate this.
     * @return bool $success
     */
    public function addLargeFile($dataFile, $filePath, $timestamp = 0, $fileComment = NULL, $extFileAttr = self::EXT_FILE_ATTR_FILE)   {
        if ($this->isFinalized) {
            return FALSE;
        }

        if (is_string($dataFile) && is_file($dataFile)) {
            $this->processFile($dataFile, $filePath, $timestamp, $fileComment, $extFileAttr);
        } else if (is_resource($dataFile) && get_resource_type($dataFile) == "stream") {
            $fh = $dataFile;
            $this->openStream($filePath, $timestamp, $fileComment, $extFileAttr);

            while (!feof($fh)) {
                $this->addStreamData(fread($fh, $this->streamChunkSize));
            }
            $this->closeStream($this->addExtraField);
        }
        return TRUE;
    }

    /**
     * Create a stream to be used for large entries.
     *
     * @param string $filePath    Filepath and name to be used in the archive.
     * @param int    $timestamp   (Optional) Timestamp for the added file, if omitted or set to 0, the current time will be used.
     * @param string $fileComment (Optional) Comment to be added to the archive for this file. To use fileComment, timestamp must be given.
     * @param int    $extFileAttr (Optional) The external file reference, use generateExtAttr to generate this.
     * @throws Exception Throws an exception in case of errors
     * @return bool $success
     */
    public function openStream($filePath, $timestamp = 0, $fileComment = null, $extFileAttr = self::EXT_FILE_ATTR_FILE)   {
        if (!function_exists('sys_get_temp_dir')) {
            throw new Exception("Zip " . self::VERSION . " requires PHP version 5.2.1 or above if large files are used.");
        }

        if ($this->isFinalized) {
            return FALSE;
        }

        $this->zipflush();

        if (strlen($this->streamFilePath) > 0) {
            $this->closeStream();
        }

        $this->streamFile = self::getTemporaryFile();
        $this->streamData = fopen($this->streamFile, "wb");
        $this->streamFilePath = $filePath;
        $this->streamTimestamp = $timestamp;
        $this->streamFileComment = $fileComment;
        $this->streamFileLength = 0;
		$this->streamExtFileAttr = $extFileAttr;

        return TRUE;
    }

    /**
     * Add data to the open stream.
     *
     * @param string $data
     * @throws Exception Throws an exception in case of errors
     * @return mixed length in bytes added or FALSE if the archive is finalized or there are no open stream.
     */
    public function addStreamData($data) {
        if ($this->isFinalized || strlen($this->streamFilePath) == 0) {
            return FALSE;
        }

        $length = fwrite($this->streamData, $data, strlen($data));
        if ($length != strlen($data)) {
			throw new Exception("File IO: Error writing; Length mismatch: Expected " . strlen($data) . " bytes, wrote " . ($length === FALSE ? "NONE!" : $length));
		}
		$this->streamFileLength += $length;
        
		return $length;
    }

    /**
     * Close the current stream.
     *
     * @return bool $success
     */
    public function closeStream() {
        if ($this->isFinalized || strlen($this->streamFilePath) == 0) {
            return FALSE;
        }

        fflush($this->streamData);
        fclose($this->streamData);

        $this->processFile($this->streamFile, $this->streamFilePath, $this->streamTimestamp, $this->streamFileComment, $this->streamExtFileAttr);

        $this->streamData = null;
        $this->streamFilePath = null;
        $this->streamTimestamp = null;
        $this->streamFileComment = null;
        $this->streamFileLength = 0;
		$this->streamExtFileAttr = null;

        // Windows is a little slow at times, so a millisecond later, we can unlink this.
        unlink($this->streamFile);

        $this->streamFile = null;

        return TRUE;
    }

    private function processFile($dataFile, $filePath, $timestamp = 0, $fileComment = null, $extFileAttr = self::EXT_FILE_ATTR_FILE) {
        if ($this->isFinalized) {
            return FALSE;
        }

        $tempzip = self::getTemporaryFile();

        $zip = new ZipArchive;
        if ($zip->open($tempzip) === TRUE) {
            $zip->addFile($dataFile, 'file');
            $zip->close();
        }

        $file_handle = fopen($tempzip, "rb");
        $stats = fstat($file_handle);
        $eof = $stats['size']-72;

        fseek($file_handle, 6);

        $gpFlags = fread($file_handle, 2);
        $gzType = fread($file_handle, 2);
        fread($file_handle, 4);
        $fileCRC32 = fread($file_handle, 4);
        $v = unpack("Vval", fread($file_handle, 4));
        $gzLength = $v['val'];
        $v = unpack("Vval", fread($file_handle, 4));
        $dataLength = $v['val'];

        $this->buildZipEntry($filePath, $fileComment, $gpFlags, $gzType, $timestamp, $fileCRC32, $gzLength, $dataLength, $extFileAttr);

        fseek($file_handle, 34);
        $pos = 34;

        while (!feof($file_handle) && $pos < $eof) {
            $datalen = $this->streamChunkSize;
            if ($pos + $this->streamChunkSize > $eof) {
                $datalen = $eof-$pos;
            }
            $data = fread($file_handle, $datalen);
            $pos += $datalen;

            $this->zipwrite($data);
        }

        fclose($file_handle);

        unlink($tempzip);
    }

    /**
     * Close the archive.
     * A closed archive can no longer have new files added to it.
     *
     * @return bool $success
     */
    public function finalize() {
        if (!$this->isFinalized) {
            if (strlen($this->streamFilePath) > 0) {
                $this->closeStream();
            }
            $cd = implode("", $this->cdRec);

            $cdRecSize = pack("v", sizeof($this->cdRec));
            $cdRec = $cd . self::ZIP_END_OF_CENTRAL_DIRECTORY
            . $cdRecSize . $cdRecSize
            . pack("VV", strlen($cd), $this->offset);
            if (!empty($this->zipComment)) {
                $cdRec .= pack("v", strlen($this->zipComment)) . $this->zipComment;
            } else {
                $cdRec .= "\x00\x00";
            }

            $this->zipwrite($cdRec);

            $this->isFinalized = TRUE;
            $this->cdRec = NULL;

            return TRUE;
        }
        return FALSE;
    }

    /**
     * Get the handle ressource for the archive zip file.
     * If the zip haven't been finalized yet, this will cause it to become finalized
     *
     * @return zip file handle
     */
    public function getZipFile() {
        if (!$this->isFinalized) {
            $this->finalize();
        }

        $this->zipflush();

        rewind($this->zipFile);

        return $this->zipFile;
    }

    /**
     * Get the zip file contents
     * If the zip haven't been finalized yet, this will cause it to become finalized
     *
     * @return zip data
     */
    public function getZipData() {
        if (!$this->isFinalized) {
            $this->finalize();
        }
        if (!is_resource($this->zipFile)) {
            return $this->zipData;
        } else {
            rewind($this->zipFile);
            $filestat = fstat($this->zipFile);
            return fread($this->zipFile, $filestat['size']);
        }
    }

	/**
	 * Send the archive as a zip download
	 *
	 * @param String $fileName The name of the Zip archive, in ISO-8859-1 (or ASCII) encoding, ie. "archive.zip". Optional, defaults to NULL, which means that no ISO-8859-1 encoded file name will be specified.
	 * @param String $contentType Content mime type. Optional, defaults to "application/zip".
	 * @param String $utf8FileName The name of the Zip archive, in UTF-8 encoding. Optional, defaults to NULL, which means that no UTF-8 encoded file name will be specified.
	 * @param bool $inline Use Content-Disposition with "inline" instead of "attached". Optional, defaults to FALSE.
	 * @throws Exception Throws an exception in case of errors
	 * @return bool Always returns true (for backward compatibility).
	*/
	function sendZip($fileName = null, $contentType = "application/zip", $utf8FileName = null, $inline = false) {
		if (!$this->isFinalized) {
			$this->finalize();
		}
		$headerFile = null;
		$headerLine = null;
		if(headers_sent($headerFile, $headerLine)) {
        	throw new Exception("Unable to send file '$fileName'. Headers have already been sent from '$headerFile' in line $headerLine");
		}
		if(ob_get_contents() !== false && strlen(ob_get_contents())) {
			throw new Exception("Unable to send file '$fileName'. Output buffer contains the following text (typically warnings or errors):\n" . ob_get_contents());
		}
		if(@ini_get('zlib.output_compression')) {
			@ini_set('zlib.output_compression', 'Off');
		}
		header("Pragma: public");
		header("Last-Modified: " . @gmdate("D, d M Y H:i:s T"));
		header("Expires: 0");
		header("Accept-Ranges: bytes");
		header("Connection: close");
		header("Content-Type: " . $contentType);
		$cd = "Content-Disposition: ";
		if ($inline) {
			$cd .= "inline";
		} else {
			$cd .= "attached";
		}
		if ($fileName) {
			$cd .= '; filename="' . $fileName . '"';
		}
		if ($utf8FileName) {
			$cd .= "; filename*=UTF-8''" . rawurlencode($utf8FileName);
		}
		header($cd);
		header("Content-Length: ". $this->getArchiveSize());
		if (!is_resource($this->zipFile)) {
			echo $this->zipData;
		} else {
			rewind($this->zipFile);
			while (!feof($this->zipFile)) {
				echo fread($this->zipFile, $this->streamChunkSize);
			}
		}
		return true;
	}

    /**
     * Return the current size of the archive
     *
     * @return $size Size of the archive
     */
    public function getArchiveSize() {
        if (!is_resource($this->zipFile)) {
            return strlen($this->zipData);
        }
        $filestat = fstat($this->zipFile);

        return $filestat['size'];
    }

    /**
     * Calculate the 2 byte dostime used in the zip entries.
     *
     * @param int $timestamp
     * @return 2-byte encoded DOS Date
     */
    private function getDosTime($timestamp = 0) {
        $timestamp = (int)$timestamp;
        $oldTZ = @date_default_timezone_get();
        date_default_timezone_set('UTC');
        $date = ($timestamp == 0 ? getdate() : getdate($timestamp));
        date_default_timezone_set($oldTZ);
        if ($date["year"] >= 1980) {
            return pack("V", (($date["mday"] + ($date["mon"] << 5) + (($date["year"]-1980) << 9)) << 16) |
                    (($date["seconds"] >> 1) + ($date["minutes"] << 5) + ($date["hours"] << 11)));
        }
        return "\x00\x00\x00\x00";
    }

    /**
     * Build the Zip file structures
     *
     * @param string $filePath
     * @param string $fileComment
     * @param string $gpFlags
     * @param string $gzType
     * @param int    $timestamp
     * @param string $fileCRC32
     * @param int    $gzLength
     * @param int    $dataLength
     * @param int    $extFileAttr Use self::EXT_FILE_ATTR_FILE for files, self::EXT_FILE_ATTR_DIR for Directories.
     */
    private function buildZipEntry($filePath, $fileComment, $gpFlags, $gzType, $timestamp, $fileCRC32, $gzLength, $dataLength, $extFileAttr) {
        $filePath = str_replace("\\", "/", $filePath);
        $fileCommentLength = (empty($fileComment) ? 0 : strlen($fileComment));
        $timestamp = (int)$timestamp;
        $timestamp = ($timestamp == 0 ? time() : $timestamp);

        $dosTime = $this->getDosTime($timestamp);
        $tsPack = pack("V", $timestamp);

        if (!isset($gpFlags) || strlen($gpFlags) != 2) {
            $gpFlags = "\x00\x00";
        }

        $isFileUTF8 = mb_check_encoding($filePath, "UTF-8") && !mb_check_encoding($filePath, "ASCII");
        $isCommentUTF8 = !empty($fileComment) && mb_check_encoding($fileComment, "UTF-8") && !mb_check_encoding($fileComment, "ASCII");
		
		$localExtraField = "";
		$centralExtraField = "";
		
		if ($this->addExtraField) {
            $localExtraField .= "\x55\x54\x09\x00\x03" . $tsPack . $tsPack . Zip::EXTRA_FIELD_NEW_UNIX_GUID;
			$centralExtraField .= "\x55\x54\x05\x00\x03" . $tsPack . Zip::EXTRA_FIELD_NEW_UNIX_GUID;
		}
		
		if ($isFileUTF8 || $isCommentUTF8) {
            $flag = 0;
            $gpFlagsV = unpack("vflags", $gpFlags);
            if (isset($gpFlagsV['flags'])) {
                $flag = $gpFlagsV['flags'];
            }
            $gpFlags = pack("v", $flag | (1 << 11));
			
			if ($isFileUTF8) {
				$utfPathExtraField = "\x75\x70"
					. pack ("v", (5 + strlen($filePath)))
					. "\x01" 
					.  pack("V", crc32($filePath))
					. $filePath;

				$localExtraField .= $utfPathExtraField;
				$centralExtraField .= $utfPathExtraField;
			}
			if ($isCommentUTF8) {
				$centralExtraField .= "\x75\x63" // utf8 encoded file comment extra field
					. pack ("v", (5 + strlen($fileComment)))
					. "\x01"
					. pack("V", crc32($fileComment))
					. $fileComment;
			}
        }

        $header = $gpFlags . $gzType . $dosTime. $fileCRC32
			. pack("VVv", $gzLength, $dataLength, strlen($filePath)); // File name length

        $zipEntry  = self::ZIP_LOCAL_FILE_HEADER
			. self::ATTR_VERSION_TO_EXTRACT
			. $header
			. pack("v", strlen($localExtraField)) // Extra field length
			. $filePath // FileName
			. $localExtraField; // Extra fields

		$this->zipwrite($zipEntry);

        $cdEntry  = self::ZIP_CENTRAL_FILE_HEADER
			. self::ATTR_MADE_BY_VERSION
			. ($dataLength === 0 ? "\x0A\x00" : self::ATTR_VERSION_TO_EXTRACT)
			. $header
			. pack("v", strlen($centralExtraField)) // Extra field length
			. pack("v", $fileCommentLength) // File comment length
			. "\x00\x00" // Disk number start
			. "\x00\x00" // internal file attributes
			. pack("V", $extFileAttr) // External file attributes
			. pack("V", $this->offset) // Relative offset of local header
			. $filePath // FileName
			. $centralExtraField; // Extra fields

		if (!empty($fileComment)) {
            $cdEntry .= $fileComment; // Comment
        }

        $this->cdRec[] = $cdEntry;
        $this->offset += strlen($zipEntry) + $gzLength;
    }

    private function zipwrite($data) {
        if (!is_resource($this->zipFile)) {
            $this->zipData .= $data;
        } else {
            fwrite($this->zipFile, $data);
            fflush($this->zipFile);
        }
    }

    private function zipflush() {
        if (!is_resource($this->zipFile)) {
            $this->zipFile = tmpfile();
            fwrite($this->zipFile, $this->zipData);
            $this->zipData = NULL;
        }
    }

    /**
     * Join $file to $dir path, and clean up any excess slashes.
     *
     * @param string $dir
     * @param string $file
     */
    public static function pathJoin($dir, $file) {
        if (empty($dir) || empty($file)) {
            return self::getRelativePath($dir . $file);
        }
        return self::getRelativePath($dir . '/' . $file);
    }

    /**
     * Clean up a path, removing any unnecessary elements such as /./, // or redundant ../ segments.
     * If the path starts with a "/", it is deemed an absolute path and any /../ in the beginning is stripped off.
     * The returned path will not end in a "/".
	 *
	 * Sometimes, when a path is generated from multiple fragments, 
	 *  you can get something like "../data/html/../images/image.jpeg"
	 * This will normalize that example path to "../data/images/image.jpeg"
     *
     * @param string $path The path to clean up
     * @return string the clean path
     */
    public static function getRelativePath($path) {
        $path = preg_replace("#/+\.?/+#", "/", str_replace("\\", "/", $path));
        $dirs = explode("/", rtrim(preg_replace('#^(?:\./)+#', '', $path), '/'));

        $offset = 0;
        $sub = 0;
        $subOffset = 0;
        $root = "";

        if (empty($dirs[0])) {
            $root = "/";
            $dirs = array_splice($dirs, 1);
        } else if (preg_match("#[A-Za-z]:#", $dirs[0])) {
            $root = strtoupper($dirs[0]) . "/";
            $dirs = array_splice($dirs, 1);
        }

        $newDirs = array();
        foreach ($dirs as $dir) {
            if ($dir !== "..") {
                $subOffset--;
                $newDirs[++$offset] = $dir;
            } else {
                $subOffset++;
                if (--$offset < 0) {
                    $offset = 0;
                    if ($subOffset > $sub) {
                        $sub++;
                    }
                }
            }
        }

        if (empty($root)) {
            $root = str_repeat("../", $sub);
        }
        return $root . implode("/", array_slice($newDirs, 0, $offset));
    }

	/**
	 * Create the file permissions for a file or directory, for use in the extFileAttr parameters.
	 *
	 * @param int   $owner Unix permisions for owner (octal from 00 to 07)
	 * @param int   $group Unix permisions for group (octal from 00 to 07)
	 * @param int   $other Unix permisions for others (octal from 00 to 07)
	 * @param bool  $isFile
	 * @return EXTRERNAL_REF field.
	 */
	public static function generateExtAttr($owner = 07, $group = 05, $other = 05, $isFile = true) {
		$fp = $isFile ? self::S_IFREG : self::S_IFDIR;
		$fp |= (($owner & 07) << 6) | (($group & 07) << 3) | ($other & 07);

		return ($fp << 16) | ($isFile ? self::S_DOS_A : self::S_DOS_D);
	}

	/**
	 * Get the file permissions for a file or directory, for use in the extFileAttr parameters.
	 *
	 * @param string $filename
	 * @return external ref field, or FALSE if the file is not found.
	 */
	public static function getFileExtAttr($filename) {
		if (file_exists($filename)) {
			$fp = fileperms($filename) << 16;
			return $fp | (is_dir($filename) ? self::S_DOS_D : self::S_DOS_A);
		}
		return FALSE;
	}
	/**
	 * Returns the path to a temporary file.
	 * @return string
	 */
	private static function getTemporaryFile() {
		if(is_callable(self::$temp)) {
			$temporaryFile = @call_user_func(self::$temp);
			if(is_string($temporaryFile) && strlen($temporaryFile) && is_writable($temporaryFile)) {
				return $temporaryFile;
			}
		}
		$temporaryDirectory = (is_string(self::$temp) && strlen(self::$temp)) ? self::$temp : sys_get_temp_dir();
		return tempnam($temporaryDirectory, 'Zip');
	}
}








class SGAntiVirus_scanner
{
    public static  $scanner_version = '2.0';
    public static  $debug = true;
    
	public static  $bool_list = array(0 => 'FALSE', 1 => 'TRUE');
	
	public static $SITEGUARDING_SERVER = 'http://www.siteguarding.com/ext/antivirus/index.php';
    
    var $antivirus_version = '';
    var $antivirus_platform = '';
    var $antivirus_cms = '';
    
    var $work_dir = '';
    var $tmp_dir = '';
    var $membership = '';
    var $scan_path = '';
    var $access_key = '';
    var $domain = '';
    var $email = '';
    var $session_report_key = '';
    
    var $exclude_folders_real = array();
    
    
    
	public function AntivirusFinished()
	{
	    if (self::$debug) self::DebugLog('line');
        
	    $reason = error_get_last();
        if (self::$debug) self::DebugLog(print_r($reason, true));
		if (self::$debug) self::DebugLog('PHP process has been terminated');
		
		$fp = fopen($this->tmp_dir.'flag_terminated.tmp', 'w');
		$a = date("Y-m-d H:i:s")." Terminated";
		fwrite($fp, $a);
		fclose($fp);
        
        if ($reason['type'] == 1) echo 'Error: '.$reason['message'].' File: '.$reason['message'].' Line: '.$reason['line'];	
	}


	
	public function AntivirusFileLock()
	{
	    $lockFile = $this->tmp_dir.'scan.lock';
		
		$lockFp = fopen($lockFile, 'w');
		
		flock($lockFp, LOCK_UN);
		unlink($lockFile);
	}
    


    
	public function scanner($check_session = true, $show_results = true)
	{
	    // Start scanning process
        error_reporting(0);
		ini_set('memory_limit', '256M');
        
	    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') define(DIRSEP, '\\');
		else define(DIRSEP, '/');
        
        
		// Skip the 2nd scan process
		$lockFile = $this->tmp_dir.'scan.lock';
		
		if (file_exists($lockFile) && (time() - filemtime($lockFile)) < 60*5)
		{
			$error_msg = 'Another Scanning Process in the memory. Exit.';
			if (self::$debug) self::DebugLog($error_msg);
			exit;
		}
		
		register_shutdown_function('self::AntivirusFileLock');
		
		$lockFp = fopen($lockFile, 'w');
        
        // Register any shutdown of the script
        register_shutdown_function('self::AntivirusFinished');
        
		
        
		$error_msg = 'Start Scan Process ver. '.$this->antivirus_version.' [scanner ver. '.self::$scanner_version.']';
		if (self::$debug) self::DebugLog($error_msg, true);
		
		
        
        // Load extra settings
		if (file_exists($this->work_dir.'settings.php'))
		{
			$error_msg = '=> Extra settings loaded';
			if (self::$debug) self::DebugLog($error_msg);
			
			require_once($this->work_dir.'settings.php');	
            
            if (count($avp_settings))
            {
                foreach ($avp_settings as $k => $v)
                {
                    $v_txt = $v;
                    if ($v === false) $v_txt = 'BOOL: false';
                    if ($v === true) $v_txt = 'BOOL: true';
                    
            		$error_msg = 'Setting Value: '.strtoupper($k).' = '.$v_txt;
            		if (self::$debug) self::DebugLog($error_msg);
                        
                    if (strtolower($v) == 'false') $v = false;
                    if (strtolower($v) == 'true') $v = true;
                    define(strtoupper($k), $v);
                }
            }
		}
        
        

		// Analyze of exclude folders
		if (file_exists($this->work_dir.'exclude_folders.php'))
		{
			$error_msg = '=> Exclude folders file loaded';
			if (self::$debug) self::DebugLog($error_msg);
			
			require_once($this->work_dir.'exclude_folders.php');	
		}
		
		
	
		$tmp_result = set_time_limit ( 7200 );
		
		$error_msg = 'Change Time limit: '.self::$bool_list[intval($tmp_result)].' , Value: '.ini_get('max_execution_time');
		if (self::$debug) self::DebugLog($error_msg);
		
		$error_msg = 'Current Memory limit: '.ini_get('memory_limit');
		if (self::$debug) self::DebugLog($error_msg);

		$error_msg = 'OS info: '.PHP_OS.' ('.php_uname().')';
		if (self::$debug) self::DebugLog($error_msg);
		
		$error_msg = 'PHP ver: '.PHP_VERSION;
		if (self::$debug) self::DebugLog($error_msg);
		
		unlink($this->tmp_dir.'flag_terminated.tmp');
        unlink($this->tmp_dir.'filelist.txt');
		
	
        /*if (!class_exists("HTTPClient"))
        {
            include_once($this->work_dir.'HttpClient.class.php');
        }
		
		$HTTPClient = new HTTPClient();*/
		
	
		// Some Init data
		$membership = $this->membership;
		$scan_path = $this->scan_path; 
		$access_key = $this->access_key;
		$domain = $this->domain;
		$email = $this->email;
		$session_report_key = $this->session_report_key; 
		
			// Some logs
			$error_msg = 'Domain: '.$domain;
			if (self::$debug) self::DebugLog($error_msg);
			
			$error_msg = 'Scan path: '.$scan_path;
			if (self::$debug) self::DebugLog($error_msg);
			
			$error_msg = 'Session report key: '.$session_report_key;
			if (self::$debug) self::DebugLog($error_msg);
            
			$error_msg = 'Report URL: https://www.siteguarding.com/antivirus/viewreport?report_id='.$session_report_key;
			if (self::$debug) self::DebugLog($error_msg);
			
			$error_msg = 'TMP folder: '.$this->tmp_dir;
			if (self::$debug) self::DebugLog($error_msg);
			
		if (trim($domain) == '') {$error_msg = 'Domain is empty. Please contact SiteGuarding.com support.';echo $error_msg;if (self::$debug) self::DebugLog($error_msg);exit;}
		if (trim($session_report_key) == '') {$error_msg = 'Session key is empty. Please contact SiteGuarding.com support.';echo $error_msg;if (self::$debug) self::DebugLog($error_msg);exit;}
		if (trim($scan_path) == '') {$error_msg = 'Scan Path is empty. Please contact SiteGuarding.com support.';echo $error_msg;if (self::$debug) self::DebugLog($error_msg);exit;}
			
		
		//session_start();
		$current_task = 0;
		$total_tasks = 0;
		$total_tasks += 1;	// Analyze what way to use for packing
		$total_tasks += 1;	// Pack files
		$total_tasks += 1;	// Send files
		$total_tasks += 1;	// Get report

		
		/**
		 * Analyze what way to use for packing
		 */
	 	$ssh_flag = false;
		if ( function_exists('exec') ) 
		{
			// Pack files with ssh 
			$ssh_flag = true;
		}
        if (defined('SETTINGS_ONLY_ZIP') && SETTINGS_ONLY_ZIP) $ssh_flag = false;
		// Update progress
		$current_task += 1;
		self::UpdateProgressValue($current_task, $total_tasks, 'Initialization.');
		
        
        if (self::$debug) self::DebugLog('line');
        


        
        $files_list = array();
        if (defined('DEBUG_FILELIST') && DEBUG_FILELIST) self::DebugFile($this->work_dir, true);
        
		$error_msg = 'Collecting info about the files [METHOD 2]';
		if (self::$debug) self::DebugLog($error_msg);        
        
        
        $exclude_folders_real = array();
		if (count($exclude_folders))
		{
			foreach ($exclude_folders as $k => $ex_folder)
			{
				$ex_folder = $scan_path.trim($ex_folder);
				$exclude_folders_real[$k] = trim(str_replace(DIRSEP.DIRSEP, DIRSEP, $ex_folder));	
			}
		}
		else $exclude_folders_real = array(); 
        $this->exclude_folders_real = $exclude_folders_real; 
        
        
		$error_msg = 'Excluded Folders: '.count($exclude_folders_real);
		if (self::$debug) self::DebugLog($error_msg);
		
		$error_msg = print_r($exclude_folders_real, true);
		if (self::$debug && count($exclude_folders_real) > 0) self::DebugLog($error_msg); 
        
        $dirList = array();
        $dirList[] = $scan_path;
        
        
 
                
        // Scan all dirs
        while (true) 
        {
            $dirList = array_merge(self::ScanFolder(array_shift($dirList), $files_list), $dirList);
            if (count($dirList) < 1) break;
        }
        
        
		$error_msg = 'Save collected file_list';
		if (self::$debug) self::DebugLog($error_msg);

		$collected_filelist = $this->tmp_dir.'filelist.txt';

		$fp = fopen($collected_filelist, 'w');
		$status = fwrite($fp, implode("\n", $files_list));
		fclose($fp);
		if ($status === false)
		{
			$error_msg = 'Cant save information about the collected files '.$collected_filelist;
			if (self::$debug) self::DebugLog($error_msg);
			
			// Turn ZIP mode
			$ssh_flag = false;
		}
		
		$error_msg = 'Total files: '.count($files_list);
		if (self::$debug) self::DebugLog($error_msg);
         
        
        

        
        


        if (self::$debug) self::DebugLog('line');



	
		if ($ssh_flag)
		{
			// SSH way
				$error_msg = 'Start - Pack with SSH';
				if (self::$debug) self::DebugLog($error_msg);
				
			$cmd = 'cd '.$scan_path.''."\n".'tar -czf '.$this->tmp_dir.'pack.tar -T '.$collected_filelist;
			$output = array();
			$result = exec($cmd, $output);
			
			if (file_exists($this->tmp_dir.'pack.tar') === false) 
			{
				$ssh_flag = false;
				
				$error_msg = 'Change pack method from SSH to PHP (ZipArchive)';
				if (self::$debug) self::DebugLog($error_msg);
			}
		}
		
        
        
    	if (!$ssh_flag) 
    	{
    		// PHP way
    			$error_msg = 'Start - Pack with ZipArchive';
    			if (self::$debug) self::DebugLog($error_msg);
    		
    	    	$file_zip = $this->tmp_dir.'pack.zip';
    	    	if (file_exists($file_zip)) unlink($file_zip);
    	    	$pack_dir = $scan_path;
                
                	
    	    if (class_exists('ZipArchive') && ( defined('DISABLE_ZIPARCHIVE') && DISABLE_ZIPARCHIVE === false ) )
    	    {
    	        // open archive
    	        $zip = new ZipArchive;
    	        if ($zip->open($file_zip, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === TRUE) 
    	        {
    	            foreach ($files_list as $file_name) 
    	            {
    	            	$file_name = $this->scan_path.$file_name;
    	                if( strstr(realpath($file_name), "stark") == FALSE) 
    					{
    						$short_key = str_replace($scan_path, "", $file_name);
    	                	$s = $zip->addFile(realpath($file_name), $short_key);
    		                if (!$s) 
    		                {
    		                	$error_msg = 'Couldnt add file: '.$file_name; 
    		                	if (self::$debug) self::DebugLog($error_msg);
    		                }
    	            	}
    					
    				}
    	             // close and save archive
    	            $zip->close();
    	            
    	            //$result['msg'][] = 'Archive created successfully'; 
    	        }
    	        else {
    	        	$error_msg = 'Error: Couldnt open ZIP archive.';
    	        	echo $error_msg;
    	            self::UpdateProgressValue($current_task, $total_tasks, $error_msg);
    				if (self::$debug) self::DebugLog($error_msg);
    				exit;
    	        }
    	
    	    }
    	    else {
    	    	$error_msg =  'Error: ZipArchive class is not exist.';
    	        if (self::$debug) self::DebugLog($error_msg);
    	    }
    	    
    		$error_msg = 'ZipArchive method - finished';
    		if (self::$debug) self::DebugLog($error_msg);
    		
    		// Check if zip file exists
    		if (!file_exists($file_zip))
    		{
    			$error_msg = 'Error: zip file is not exists. Use OwnZipClass';
    			if (self::$debug) self::DebugLog($error_msg);
    			
    			$error_msg = 'OwnZipClass method - started';
    			if (self::$debug) self::DebugLog($error_msg);
                
    				$zip = new Zip();
    				$zip->setZipFile($file_zip);
    	            foreach ($files_list as $file_name_short) 
    	            {
    	            	$file_name = trim($this->scan_path.$file_name_short);
						
							if (defined('DEBUG_ZIP_ADDFILES') && DEBUG_ZIP_ADDFILES === true)
							{
								$error_msg = 'Zip Add: '.$file_name;
								if (self::$debug) self::DebugLog($error_msg);
							}
							
    	            	$handle = fopen($file_name, "r");
    	            	if (filesize($file_name) > 0) $zip->addFile(fread($handle, filesize($file_name)), $file_name_short, filectime($file_name), NULL, TRUE, Zip::getFileExtAttr($file_name));
    	            	fclose($handle);
    	           	}
    	           	$zip->finalize();
               	
    			$error_msg = 'OwnZipClass method - finished';
    			if (self::$debug) self::DebugLog($error_msg);
                
                $ssh_flag = false; 
    		}
    		
    	}
        
        
        
        
        
		// Update progress
		$current_task += 1;
		self::UpdateProgressValue($current_task, $total_tasks, 'Collecting information about the files.');


		/**
		 * Send files to SG server
		 */
		if ($ssh_flag)
		{
	 		$archive_filename = $this->tmp_dir."pack.tar";
	 		$archive_format = 'tar';
		} else {
			$archive_filename = $this->tmp_dir."pack.zip";
			$archive_format = 'zip';
		}
		$error_msg = 'Pack file: '.$archive_filename;
		if (self::$debug) self::DebugLog($error_msg);

		
	 	
	 	// Check if pack file is exist
		if (file_exists($archive_filename) === false) 
		{
			$error_msg = 'Error: Pack file is not exist. Probably not enough space on the server.';
			if (self::$debug) self::DebugLog($error_msg);
			echo $error_msg;
			exit;
		}
        
		$tar_size = filesize($archive_filename);
		$error_msg = 'Pack file is '.round($tar_size/1024/1024, 2).'Mb';
		if (self::$debug) self::DebugLog($error_msg);
        
        
        
        if (self::$debug) self::DebugLog('line');
		
		

		
		
		$error_msg = 'Start - Send Packed files to SG server';
		if (self::$debug) self::DebugLog($error_msg);
		
        $archive_file_url = "/".str_replace($this->scan_path, "", $this->tmp_dir).'pack.'.$archive_format;
        $archive_file_url = str_replace("\\", "/", $archive_file_url);
		$error_msg = 'Pack URL: '.$archive_file_url;
		if (self::$debug) self::DebugLog($error_msg);
		
		if ($tar_size < 32 * 1024 * 1024 || $membership == 'pro')
    	{
    		// Send file
    		$post_data = base64_encode(json_encode(array(
    				'domain' => $domain,
    				'access_key' => $access_key,
    				'email' => $email,
    				'session_report_key' => $session_report_key,
    				'archive_format' => $archive_format,
    				'archive_file_url' => $archive_file_url))
    		);
    
    		$flag_CallBack = false;
    		if (defined('CALLBACK_PACK_FILE') && CALLBACK_PACK_FILE )
    		{	// Callback option
    			$flag_CallBack = true;
    		}
    		else {
    			$result = self::UploadSingleFile($archive_filename, 'uploadfiles_ver2', $post_data);
    			if ($result === false)
    			{
    				$error_msg = 'Can not upload pack file for analyze';
    				if (self::$debug) self::DebugLog($error_msg);
    				
    				$flag_CallBack = true;
    			}
    			else {
    				$error_msg = 'Pack file sent for analyze - OK';
    				if (self::$debug) self::DebugLog($error_msg);
    				
    				$flag_CallBack = false;
    			}
    		}
    		
    		
    		// CallBack method
    		if ($flag_CallBack)
    		{
    			$error_msg = 'Start to use CallBack method';
    			if (self::$debug) self::DebugLog($error_msg);
    			
    			
    			$post_data = base64_encode(json_encode(array(
    					'domain' => $domain,
    					'access_key' => $access_key,
    					'email' => $email,
    					'session_report_key' => $session_report_key,
    					'archive_format' => $archive_format,
    					'archive_file_url' => $archive_file_url))
    			);
    			
    			$result = self::UploadSingleFile_Callback($post_data);
    			
    			if ($result === false)
    			{
    				$error_msg = 'CallBack method - failed';
    				if (self::$debug) self::DebugLog($error_msg);
    				
    				$error_msg = 'Can not upload pack file for analyze';
    				if (self::$debug) self::DebugLog($error_msg);
    				echo $error_msg;
    				exit;
    			}
    			else {
    				$error_msg = 'CallBack method - OK';
    				if (self::$debug) self::DebugLog($error_msg);
    			}
    			
    		}
    
    		
    	}
		else {
			$error_msg = 'Pack file is too big ('.$error_msg.'), please contact SiteGuarding.com support or upgrade to PRO version.';
			if (self::$debug) self::DebugLog($error_msg);
			echo $error_msg;
			exit;
		}
		// Update progress
		$current_task += 1;
		self::UpdateProgressValue($current_task, $total_tasks, 'Analyzing the files. Preparing the report.');
		




        if (self::$debug) self::DebugLog('line');
        

		/**
		 * Check and Get report from SG server
		 */
		$error_msg = 'Start - Report generating';
		if (self::$debug) self::DebugLog($error_msg);
		
		for ($i = 1; $i <= 10*60; $i++)
		{
			sleep(5);

			/*$post_data = array(
				'data'=> base64_encode(json_encode(array(
					'domain' => $domain,
					'access_key' => $access_key,
					'session_report_key' => $session_report_key)))
			);*/
            
    		$post_data = base64_encode(json_encode(array(
    				'domain' => $domain,
    				'access_key' => $access_key,
    				'session_report_key' => $session_report_key)));
	
			//$result_json = $HTTPClient->post(self::$SITEGUARDING_SERVER.'?action=getreport_ver2', $post_data);
    		$link = self::$SITEGUARDING_SERVER.'?action=getreport_ver2&data='.$post_data;
    		$result_json = file_get_contents($link);
			if ($result_json === false) 
			{
				$error_msg = 'Report can not be generated. Please try again or contact support';
				if (self::$debug) self::DebugLog($error_msg);
				echo $error_msg;
				exit;
			}
			
			$result_json = (array)json_decode($result_json, true);

			//if (self::$debug) self::DebugLog(print_r($result_json, true));
            
			if ($result_json['status'] == 'ready') 
			{
				echo $result_json['text'];
                
				// Update progress
				$current_task += 1;
				self::UpdateProgressValue($current_task, $total_tasks, 'Done. Sending your report.');
				
				$error_msg = 'Done. Sending your report by email';
				if (self::$debug) self::DebugLog($error_msg);
				
				// Send email to user with the report
				$email_result = self::SendEmail($email, $result_json['text']);
                
				if ($email_result) $error_msg = 'Report Sent - OK';
                else $error_msg = 'Report Sent - FAILED'; 
				if (self::$debug) self::DebugLog($error_msg);
				
				exit;	
			}
		}
		

		
		$error_msg = 'Finished [Report is not sent]'."\n";
		if (self::$debug) self::DebugLog($error_msg);
		 
    }
    
    
    
    
    
    function ScanFolder($path, &$files_list)
    {
        $dirList = array();
    
        if ($currentDir = opendir($path)) 
        {
            while ($file = readdir($currentDir)) 
            {
                if ( $file === '.' || $file === '..' || is_link($path) ) continue;
                $file = $path . '/' . $file;
    
                
                if (is_dir($file)) 
                {
                    $folder = $file.DIRSEP;
                    $folder = str_replace(DIRSEP.DIRSEP, DIRSEP, $folder);
                    
                    // Exclude folders
                    if (count($this->exclude_folders_real))
                    {
                 		if (in_array($folder, $this->exclude_folders_real)) 
        				{
        				    if (self::$debug) self::DebugLog('--- '.$folder);
                            continue;
        				}
        				else if (self::$debug) self::DebugLog('+++ '.$folder);
                    }
                    $dirList[] = $file;
                    if (defined('DEBUG_FILELIST') && DEBUG_FILELIST) self::DebugFile($file);
                }
                else {
					if (strpos($file, '.php.') || strpos($file, '.phtml.') || strpos($file, '.php3.') || strpos($file, '.php4.') || strpos($file, '.php5.'))
					{
                        $file = str_replace($this->scan_path, "", $file);
        				if ($file[0] == "\\" || $file[0] == "/") $file[0] = "";
        				$file = trim($file);
        				$files_list[] = $file;
					}
					else {
                        // Check extension
                        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                        switch ($ext)
                        {
                            case 'inc':
                            case 'php':
                            case 'php4':
                            case 'php5':
                            case 'phtml':
                            case 'js':
                            case 'html':
                            case 'htm':
                            case 'cgi':
                            case 'pl':
                            case 'so':
                            case 'sh':
                            case 'htaccess':
                                $file = str_replace($this->scan_path, "", $file);
                				if ($file[0] == "\\" || $file[0] == "/") $file[0] = "";
                				$file = trim($file);
                				$files_list[] = $file;
                                break;
                        }
                    }
                    
                }
    
            }
            closedir($currentDir);
        }
    
        return $dirList;
    }

    

    
    
    
    function DebugFile($file, $clean_log_file = false)
    {
		if ($clean_log_file) $fp = fopen($this->tmp_dir.'debug_filelist.log', 'w');
		else {
            $file = str_replace($this->scan_path, "", $file);
    	    $fp = fopen($this->tmp_dir.'debug_filelist.log', 'a');
		}

		$a = $file."\n";
		fwrite($fp, $a);
		fclose($fp); 
    }
    
    
    
    
    
	function UpdateProgressValue($current_task, $total_tasks, $current_step_txt)
	{
		$i = round( 100*$current_task/$total_tasks, 2 );
		
		$a = array(
			'txt' => $current_step_txt,
			'progress' => $i
		);
		
		$filename = $this->tmp_dir."antivirus_last_action.log";
		$fp = fopen($filename, 'w');
		fwrite($fp, json_encode($a));
		fclose($fp);
		
		sleep(3);
	}
    
    
    
    function UploadSingleFile($file, $action, $post_data)
    {
    	$target_url = self::$SITEGUARDING_SERVER.'?action='.$action;
    	$file_name_with_full_path = $file;
    	$post = array(
    		'data' => $post_data,
    		'file_contents'=>'@'.$file_name_with_full_path
    	);
    	
    		$error_msg = 'CURL CURLOPT_INFILE: '.$file_name_with_full_path;
    		if (self::$debug) self::DebugLog($error_msg);
    		$error_msg = 'CURL CURLOPT_INFILESIZE: '.filesize($file_name_with_full_path);
    		if (self::$debug) self::DebugLog($error_msg);
    		
    
     	$ch = curl_init();
    	curl_setopt($ch, CURLOPT_URL,$target_url);
    	curl_setopt($ch, CURLOPT_POST,1);
        curl_setopt($ch, CURLOPT_SAFE_UPLOAD,false);
    	curl_setopt($ch, CURLOPT_POSTFIELDS, $post);
    	curl_setopt($ch, CURLOPT_INFILE, $file_name_with_full_path);
    	curl_setopt($ch, CURLOPT_INFILESIZE, filesize($file_name_with_full_path));
    	$result=curl_exec ($ch);
    	
    		$info = curl_getinfo($ch);
    		$error_msg = 'CURL info - '.print_r($info, true);
    		if (self::$debug) self::DebugLog($error_msg);
    		
    	$curl_error = curl_error($ch);
    	curl_close ($ch);
    	
    	if ($info['size_upload'] < 10000/*filesize($file_name_with_full_path)*/)
    	{
    		$error_msg = 'CURL uploaded file wrong size: '.$info['size_upload'];
    		if (self::$debug) self::DebugLog($error_msg);
    		
    		return false;
    	}
    
    	if (!$result) 
    	{
    		$error_msg = 'CURL upload is failed - '.$curl_error;
    		if (self::$debug) self::DebugLog($error_msg);
    		
    		return false;
    	}
    	else return true;
    }
    
    
    
    function UploadSingleFile_Callback($post_data)
    {
    	$link = self::$SITEGUARDING_SERVER.'?action=uploadfiles_callback';
    	
    	$postdata = http_build_query(
    	    array(
    	        'data' => $post_data
    	    )
    	);
    	
    	$opts = array('http' =>
    	    array(
    	        'method'  => 'POST',
    	        'header'  => 'Content-type: application/x-www-form-urlencoded',
    	        'content' => $postdata
    	    )
    	);
    	
    	$context  = stream_context_create($opts);
    	
    	$result = file_get_contents($link, false, $context);
    	
    	$result = json_decode(trim($result), true);
    	
    	if (self::$debug) self::DebugLog(print_r($result, true));
    	
    	if ($result['status'] == 'ok') return true;
    	else return false;
    }
    
    
    
    function SendEmail($email, $result, $subject = '')
    {
    	$to  = $email; // note the comma
    	
    	// subject
    	if ($subject == '') $subject = 'AntiVirus Report ['.date("Y-m-d H:i:s").']';
    	
    	// message
        $body_message = '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
<title>SiteGuarding - Professional Web Security Services!</title>
</head>
<body bgcolor="#ECECEC" style="background-color:#ECECEC;">
<table cellpadding="0" cellspacing="0" width="100%" align="center" border="0" bgcolor="#ECECEC" style="background-color: #fff;">
  <tr>
    <td width="100%" align="center" bgcolor="#ECECEC" style="padding: 5px 30px 20px 30px;">
      <table width="750" border="0" align="center" cellpadding="0" cellspacing="0" bgcolor="#fff" style="background-color: #fff;">
        <tr>
          <td width="750" bgcolor="#fff"><table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color: #fff;">
            <tr>
              <td width="350" height="60" bgcolor="#fff" style="padding: 5px; background-color: #fff;"><a href="http://www.siteguarding.com/" target="_blank"><img src="data:image/png;base64,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" alt="SiteGuarding - Protect your website from unathorized access, malware and other threat" height="60" border="0" style="display:block" /></a></td>
              <td width="400" height="60" align="right" bgcolor="#fff" style="background-color: #fff;">
              <table border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color: #fff;">
                <tr>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/login" target="_blank" style="color:#656565; text-decoration: none;">Login</a></td>
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/prices" target="_blank" style="color:#656565; text-decoration: none;">Services</a></td>
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif; font-size:11px;"><a href="http://www.siteguarding.com/en/what-to-do-if-your-website-has-been-hacked" target="_blank" style="color:#656565; text-decoration: none;">Security Tips</a></td>            
                  <td width="15"></td>
                  <td width="1" bgcolor="#656565"></td>
                  <td width="15"></td>
                  <td style="font-family:Arial, Helvetica, sans-serif;  font-size:11px;"><a href="http://www.siteguarding.com/en/contacts" target="_blank" style="color:#656565; text-decoration: none;">Contacts</a></td>
                  <td width="30"></td>
                </tr>
              </table>
              </td>
            </tr>
          </table></td>
        </tr>

        <tr>
          <td width="750" height="2" bgcolor="#D9D9D9"></td>
        </tr>
        <tr>
          <td width="750" bgcolor="#fff" ><table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color:#fff;">
            <tr>
              <td width="750" height="30"></td>
            </tr>
            <tr>
              <td width="750">
                <table width="750" border="0" cellspacing="0" cellpadding="0" bgcolor="#fff" style="background-color:#fff;">
                <tr>
                  <td width="30"></td>
                  <td width="690" bgcolor="#fff" align="left" style="background-color:#fff; font-family:Arial, Helvetica, sans-serif; color:#000000; font-size:12px;">
                    {MESSAGE_CONTENT}
                    <br>
                    <b>URGENT SUPPORT</b><br>
                    Not sure in the report details? Need urgent help and support. Please contact us <a href="https://www.siteguarding.com/en/contacts" target="_blank">https://www.siteguarding.com/en/contacts</a>
                  </td>
                  <td width="30"></td>
                </tr>
              </table></td>
            </tr>
            <tr>
              <td width="750" height="15"></td>
            </tr>
            <tr>
              <td width="750" height="15"></td>
            </tr>
            <tr>
              <td width="750"><table width="750" border="0" cellspacing="0" cellpadding="0">
                <tr>
                  <td width="30"></td>
                  <td width="690" align="left" style="font-family:Arial, Helvetica, sans-serif; color:#000000; font-size:12px;"><strong>How can we help?</strong><br />
                    If you have any questions please dont hesitate to contact us. Our support team will be happy to answer your questions 24 hours a day, 7 days a week. You can contact us at <a href="mailto:support@siteguarding.com" style="color:#2C8D2C;"><strong>support@siteguarding.com</strong></a>.<br />
                    <br />
                    Thanks again for choosing SiteGuarding as your security partner!<br />
                    <br />
                    <span style="color:#2C8D2C;"><strong>SiteGuarding Team</strong></span><br />
                    <span style="font-family:Arial, Helvetica, sans-serif; color:#000; font-size:11px;"><strong>We will help you to protect your website from unauthorized access, malware and other threats.</strong></span></td>
                  <td width="30"></td>
                </tr>
              </table></td>
            </tr>
            <tr>
              <td width="750" height="30"></td>
            </tr>
          </table></td>
        </tr>
        <tr>
          <td width="750" height="2" bgcolor="#D9D9D9"></td>
        </tr>
      </table>
      <table width="750" border="0" cellspacing="0" cellpadding="0">
        <tr>
          <td width="750" height="10"></td>
        </tr>
        <tr>
          <td width="750" align="center"><table border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/website-daily-scanning-and-analysis" target="_blank" style="color:#656565; text-decoration: none;">Website Daily Scanning</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/malware-backdoor-removal" target="_blank" style="color:#656565; text-decoration: none;">Malware & Backdoor Removal</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/update-scripts-on-your-website" target="_blank" style="color:#656565; text-decoration: none;">Security Analyze & Update</a></td>
              <td width="15"></td>
              <td width="1" bgcolor="#656565"></td>
              <td width="15"></td>
              <td style="font-family:Arial, Helvetica, sans-serif; color:#ffffff; font-size:10px;"><a href="http://www.siteguarding.com/en/website-development-and-promotion" target="_blank" style="color:#656565; text-decoration: none;">Website Development</a></td>
            </tr>
          </table></td>
        </tr>

        <tr>
          <td width="750" height="10"></td>
        </tr>
        <tr>
          <td width="750" align="center" style="font-family: Arial,Helvetica,sans-serif; font-size: 10px; color: #656565;">Add <a href="mailto:support@siteguarding.com" style="color:#656565">support@siteguarding.com</a> to the trusted senders list.</td>
        </tr>
      </table>
    </td>
  </tr>
</table>
</body>
</html>
';

    	$body_message = str_replace("{MESSAGE_CONTENT}", $result, $body_message);
    	
    	// To send HTML mail, the Content-type header must be set
    	$headers  = 'MIME-Version: 1.0' . "\r\n";
    	$headers .= 'Content-type: text/html; charset=UTF-8' . "\r\n";
    	
    	// Additional headers
    	$headers .= 'From: '. $to . "\r\n";
    	
    	// Mail it
    	return mail($to, $subject, $body_message, $headers);
    }
    
    
	public function DebugLog($txt, $clean_log_file = false)
	{
	    if ($txt == 'line') $txt = '-----------------------------------------------------------------------';
		if ($clean_log_file) $fp = fopen($this->tmp_dir.'debug.log', 'w');
		else $fp = fopen($this->tmp_dir.'debug.log', 'a');
		$a = date("Y-m-d H:i:s")." ".$txt."\n";
		fwrite($fp, $a);
		fclose($fp);
	}
}


?>