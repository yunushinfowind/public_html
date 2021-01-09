<?php
define("VERSION", "2.3");

error_reporting(0);
set_time_limit ( 7200 );    // 1 hour

$session_key = trim($_REQUEST['session_key']);

DebugLog('Got request');
DebugLog('Session Key: '.$session_key);

if ($session_key == '')
{
    $remote_ip = $_SERVER['REMOTE_ADDR'];
    switch ($remote_ip)
    {
        case '185.72.156.128':
        case '185.72.156.129':
        case '185.72.156.130':
        case '185.72.156.131':
        case '185.72.156.133':
            break;
        
        default:
			$txt = 'wrong remote IP: '.$remote_ip;
			DebugLog($txt);
            PrintOutput(false, $txt);
            exit;
        
    }
}
else {
    if (file_exists(dirname(__FILE__).'/config.php'))
    {
        include_once(dirname(__FILE__).'/config.php');
        $tmp_server_key = md5($_REQUEST['tmpkey'].'-'.WEBSITE_KEY);
        if ($session_key != $tmp_server_key)
        {
			$txt = 'Session key '.$session_key.' <> TMP server key '.$tmp_server_key;
			DebugLog($txt);
            PrintOutput(false, $txt);
            exit;
        }
    }
    else {
		$txt = 'Config doesnt exit';
		DebugLog($txt);
        PrintOutput(false, $txt);
        exit;
    }
    
}






/**
 * Plugin integration
 */
DebugLog('Plugin Section');
$plugin_name = trim($_REQUEST['plugin']);
if ($plugin_name != '')
{
    $task = trim($_REQUEST['task']);
    switch ($plugin_name)
    {
        case 'backup':
            switch ($task)
            {
                // /webanalyze/tunnel.php?session_key=12345&plugin=backup&task=backup_files
                case 'backup_files':
                    PLUGIN_Backup_dofiles();
                    break;
            }
            
            break;
    }
    
    exit;   // no output
}

$website_access_key = '12345678900';

$data = trim($_REQUEST['data']);
$data = json_decode(base64_decode($data), true);

$task = trim($data['task']);

    
$session_id = trim($data['session_id']);
$session_code = trim($data['session_code']);
$version = trim($data['version']);
if (VERSION < $version || $version == '')
{
    PrintOutput(false, 'Old version. Installed: '.VERSION.' Request sent from version '.$version);
    exit;
}



if (md5($session_id.$website_access_key) != $session_code) 
{
    PrintOutput(false, 'error authorization');
    exit;
}

switch ($task)
{
    case 'self_info':
        //$result = array('server' => $_SERVER);
        $result = array('version' => VERSION);
        PrintOutput(true, '', $result);
        break;
        
    case 'remove_tunnel':
        $a = unlink(__FILE__);
        if ($a) PrintOutput(true, '');
        else PrintOutput(false, 'Cant remove '.__FILE__);
        exit;
        break;
        
    case 'remove_files':
        $files = trim($data['files']);
        $files = json_decode($files, true);
        if ($files === false)
        {
            PrintOutput(false, 'wrong file list');
            exit;
        }
        $result_array = TASK_remove_files($files);
        PrintOutput($result_array['status'], $result_array['description']);
        exit;
        break;
        
    case 'restore_files':
        $files = trim($data['files']);
        $files = json_decode($files, true);
        if ($files === false)
        {
            PrintOutput(false, 'wrong file list');
            exit;
        }
        $backup_file = trim($data['backup_file']);
        if (!file_exists(dirname(__FILE__)."/backups/".$backup_file) || $backup_file == '')
        {
            PrintOutput(false, 'backup file doesnt exist or empty. File: '.$backup_file);
            exit;
        }
        $result_array = TASK_restore_files($files, $backup_file);
        PrintOutput($result_array['status'], $result_array['description']);
        exit;
        break;
        
    case 'get_files_info':
        $files = trim($data['files']);
        $files = json_decode($files, true);
        //print_r($files);
        if ($files === false)
        {
            PrintOutput(false, 'wrong file list');
            exit;
        }
        $result['file_list'] = TASK_get_files_info($files);
        $result['backups'] = GetAvailableBackupsFile(true);
        PrintOutput(true, '', $result); 
        break;
        
        
    case 'get_file_content':
        $file = trim($data['file']);
        //print_r($files);
        if ($file == '')
        {
            PrintOutput(false, 'wrong file'.print_r($data, true));
            exit;
        }
        $result = TASK_get_file_content($file);
        PrintOutput(true, '', $result);
        break;
        
        
    case 'save_file_content':
        $is_empty = intval($data['is_empty']);
        $file = trim($data['file']);
        $tmp_filename = trim($data['tmp_filename']);
        $tmp_file_md5 = trim($data['tmp_file_md5']);
        //DebugLog(print_r($data, true));
        
        if ($file == '')
        {
            PrintOutput(false, 'wrong file'.print_r($data, true));
            exit;
        }
        
        if (!$is_empty)
        {
            $file_content_info = GetRemoteFile($tmp_filename, $tmp_file_md5);
            if ($file_content_info['status'] === false)
            {
                PrintOutput(false, 'Cant get remote file [Reason: '.$file_content_info['reason'].']');
                exit;
            }
            
            $file_content = $file_content_info['content'];
        }
        else $file_content = '';

        
        chmod($file, 0644);

        $result_array = TASK_save_file_content($file, $file_content);
        PrintOutput($result_array['status'], $result_array['description']);
        break;
        
        
    default:
        PrintOutput(false, 'task '.$task.' is absent');
    
}

exit;


function GetDir()
{
    $dir = dirname(__FILE__);
    $dir = str_replace("/webanalyze", "", $dir); 
    
    return $dir;   
}


function TASK_save_file_content($file, $file_content)
{
    $dir = GetDir();
    
    $file_full = $dir.$file;
    
    $fp = fopen($file_full, 'w');
    if ($fp === false) return array('status' => false, 'description' => 'Cant open file (fopen) '.$file_full);
    $file_content = str_replace("\r\n","\n", $file_content);
    $a = fwrite($fp, $file_content);
    if ($a === false) return array('status' => false, 'description' => 'Cant save content (fwrite) '.$file_full);
    $a = fclose($fp);
    if ($a === false) return array('status' => false, 'description' => 'Cant close the file (fclose) '.$file_full);
    
    return array('status' => true, 'description' => $file_full);
}


function TASK_remove_files($files)
{
    $result_description = '';
    $result_status = true;
    
    $dir = GetDir();
    
    
    if (count($files))
    {
        foreach ($files as $file)
        {
            $file = trim($file);
            $file_full = $dir.$file;
            if (file_exists($file_full))
            {
                $a = unlink($file_full);
                if ($a === false) 
                {
                    $result_description .= $file.' - ERROR [unlink]'."\n";
                    $result_status = false;
                }
                else $result_description .= $file.' - OK'."\n";
            }
            else {
                $result_description .= $file.' - FILE ABSENTS'."\n";
            }
        }
    }
    else {
        $result_description = 'File list is empty';
        $result_status = false;
    }
    
    return array('status' => $result_status, 'description' => $result_description);
}


function TASK_restore_files($files, $backup_file)
{
    $extract_to_folder = GetDir()."/";
    $backup_file = dirname(__FILE__)."/backups/".$backup_file;
    
    // Prepare files
    /*foreach ($files as $k => $file)
    {
        if ($file[0] == "/") $file[0] = " ";
        $file = trim($file);
        $files[$k] = $file;
    }*/
    
    $result_description = '';
    $result_status = true;
    
    $zip = new ZipArchive;
    $res = $zip->open($backup_file);
    if ($res === TRUE) 
    {
		foreach ($files as $file)
		{
			if ($file[0] == "/") $file[0] = " ";
			$file = trim($file);
			
			$a = $zip->extractTo($extract_to_folder, $file);
			if ($a === false) 
			{
				$a = $zip->getFromName ($file);
				if ($a === false) $result_description .= '<font class="error2">!!! File absent in archive: '.$extract_to_folder.$file."</font>\n";
				
				$result_description .= '<font class="error2">!!! Restoring failed. Folder: '.$extract_to_folder.' File: '.$file."</font>\n";
				
				/*$result_description .= "\n"."Remove file: ".$extract_to_folder.$file."\n";;
				$unlink_status = unlink($extract_to_folder.$file);
				if ($unlink_status === false) $result_description .= '<font class="error2">Cant remove file: '.$extract_to_folder.$file."</font>\n";
				else $result_description .= 'File Removed: '.$extract_to_folder.$file."\n";
				
				$a = $zip->extractTo($extract_to_folder, $file);
				if ($a === false) $result_description .= '<font class="error2">Restoring failed. Folder: '.$extract_to_folder.' File: '.$file."</font>\n";
				else $result_description .= 'Restored to '.$extract_to_folder.$file."\n";*/
			}
			else $result_description .= 'Restored to '.$extract_to_folder.$file."\n";
			
		}
        /*$a = $zip->extractTo($extract_to_folder, $files);
        if ($a === false) $result_description .= 'Restoring failed. Folder: '.$extract_to_folder.' Files: '.print_r($files, true);
        else $result_description .= 'Restored to '.$extract_to_folder;*/

        $zip->close();
    } 
    else {
        $result_description .= 'ZipArchive open archive '.$backup_file.' - failed ';
        $result_status = false;
    }
    
    return array('status' => $result_status, 'description' => $result_description);
}



function TASK_get_file_content($file)
{
    $dir = GetDir();
    
    $file_full = $dir.$file;
    if (file_exists($file_full) === false) $file_content = 'file is not exist';
    else {
        $handle = fopen($file_full, "r");
        $file_size = filesize($file_full);
        $file_content = fread($handle, $file_size);
        fclose($handle);
    }
    
    $a = array(
        'file' => $file_full,
        'filesize' => $file_size,
        'content' => $file_content
    );
    
    return $a;
}


function TASK_get_files_info($files)
{
    $dir = GetDir();
    $a = array();
    foreach($files as $file)
    {
        $file = trim($file);
        $file_full = $dir.$file;
        if (file_exists($file_full) === false) $filesize = 'absent';
        else {
            $filesize = filesize($file_full);
            $file_md5 = md5_file($file_full);
            $file_mod = substr(sprintf('%o', fileperms($file_full)), -4);
        }

        $a[] = array(
            'file' => $file,
            'size' => $filesize,
            'md5' => $file_md5,
            'mod' => $file_mod
        );
    }
    
    return $a;
}






function GetRemoteFile($tmp_filename, $tmp_file_md5)
{
    $url = 'http://www.siteguarding.com/_get_file.php?file=tunnel_task&filename='.$tmp_filename.'&time='.time();
    $dst = dirname(__FILE__).'/tunnel.file.tmp';
    
    $filesize = CreateRemote_file_contents($url, $dst);
    
    if ($filesize !== false && $filesize > 0)
    {
        if (md5_file($dst) == $tmp_file_md5)
        {
            $handle = fopen($dst, "r");
            $contents = fread($handle, filesize($dst));
            fclose($handle);
            
            $a = array(
                'status' => true,
                'reason' => '',
                'content' => $contents
            );
        }
        else {
            $a = array(
                'status' => false,
                'reason' => 'Wrong md5',
                'content' => ''
            );
        }
    }
    else {
        $a = array(
            'status' => false,
            'reason' => 'cURL return error',
            'content' => ''
        );
    }
    
    unlink($dst);
    
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





/**
 * Plugin function
 */

function PLUGIN_Backup_dofiles()
{
    $txt = 'Start File Backup';
    DebugLog($txt, true);
    
    // Check if backup folder exists and protected
    $backups_folder = dirname(__FILE__)."/backups"; 
    if (!file_exists($backups_folder))
    {
        if (!mkdir($backups_folder))
        {
            $txt = 'Cant create '.$backups_folder;
            DebugLog($txt);
            return;
        }
        
        $content = 'order deny,allow'."\n".'deny from all';
        if (!CreateFileWithContent($backups_folder."/.htaccess", $content))
        {
            $txt = 'Cant create .htaccess';
            DebugLog($txt);
            return;
        }
    }
    
    if (!file_exists($backups_folder."/.htaccess"))
    {
        $content = '<Limit GET POST>'."\n".'order deny,allow'."\n".'deny from all'."\n".'</Limit>';
        if (!CreateFileWithContent($backups_folder."/.htaccess", $content))
        {
            $txt = 'Cant create .htaccess';
            DebugLog($txt);
            return;
        }
    }
    
    
    
    // Find and Remove old backups
    $backup_files = array();
    foreach (glob($backups_folder."/*.zip") as $filename) 
    {
        $backup_files[filemtime($filename)] = $filename; 
    }
    if (count($backup_files) > 10 )
    {
        krsort($backup_files);
        $i = 1;
        foreach ($backup_files as $filename)
        {
            if ($i > 10)
            {
                unlink($filename);
            }
            $i++;
        }
    }
    
    
    
    // Collect list of files to backup
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') 
    {	// Windows
    	define('DIRSEP', '\\');
    }
    else {
    	// Unix
    	define('DIRSEP', '/');
    }
    
    $scan_path = GetDir();
    define('SCAN_PATH', $scan_path);
    
    $files_list = array();
    $dirList = array();
    $dirList[] = $scan_path;
    
    // Scan all dirs
    while (true) 
    {
        $dirList = array_merge(ScanFolder(array_shift($dirList), $files_list), $dirList);
        if (count($dirList) < 1) break;
    }
    
    
    
    // Zip files
	$txt = 'Found '.count($files_list).' files';
    DebugLog($txt);
    
    if (class_exists('ZipArchive') && count($files_list)>0)
    {
        // open archive
        $file_zip = $backups_folder.'/files_'.date("Y-m-d_H-i").'.zip';
        
        $zip = new ZipArchive;
        if ($zip->open($file_zip, ZIPARCHIVE::CREATE | ZIPARCHIVE::OVERWRITE) === TRUE) 
        {
            foreach ($files_list as $file_name_short) 
            {
            	if ($file_name_short[0] == "/") $file_name_short[0] = " ";
				$file_name_short = trim($file_name_short); 
            	$file_name = trim(SCAN_PATH.DIRSEP.$file_name_short);
            	$file_name = str_replace("//", "/", $file_name);

                	$s = $zip->addFile($file_name, $file_name_short);
	                if (!$s) 
	                {
	                	$txt = 'Couldnt add file: '.$file_name; 
	                	DebugLog($txt);
	                }

				
			}
            // close and save archive
            $zip->close();
            
            //$result['msg'][] = 'Archive created successfully'; 
        }
        else {
        	$txt = 'Error: Couldnt open ZIP archive.';
            DebugLog($txt);
            return;
        }

    }
    else {
    	$txt =  'Error: ZipArchive class is not exist or filelist is empty.';
        DebugLog($txt);
        return;
    }
    
	$txt =  'Finished';
    DebugLog($txt);
    
    return true;
}


function GetAvailableBackupsFile($short = false)
{
    $backups_folder = dirname(__FILE__)."/backups";
    
    $backup_files = array();
    foreach (glob($backups_folder."/*.zip") as $filename) 
    {
        if ($short) $filename = str_replace($backups_folder, "", $filename);
        
        $backup_files[] = $filename; 
    }
    
    sort($backup_files);
    
    return $backup_files;
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
                
                $dirList[] = $file;
            }
            else {

                    // Check extension
                    $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                    switch ($ext)
                    {
                        case 'inc':
                        case 'php':
                        case 'js':
                        case 'html':
                        case 'htm':
                            $file = str_replace(SCAN_PATH, "", $file);
            				if ($file[0] == "\\" || $file[0] == "/") $file[0] = "";
            				$file = trim($file);
            				$files_list[] = $file;
                            break;
                    }
                
                
            }

        }
        closedir($currentDir);
    }

    return $dirList;
}


function PrintOutput($result_type, $result_reason = '', $result_data = array())
{
    $a = array();
    if ($result_type) $a['status'] = 'ok';
    else $a['status'] = 'error';
    
    $a['description'] = $result_reason;
    
    $a['data'] = $result_data;
    
    echo json_encode($a);
}

function CreateFileWithContent($file, $content)
{
    $fp = fopen($file, 'w');
    if ($fp === false) return false;
    if (fwrite($fp, $content) === false) return false;
    fclose($fp);
    
    return true;
}

function DebugLog($txt, $clean_log_file = false)
{
	if ($clean_log_file) $fp = fopen(dirname(__FILE__).'/tunnel_debug.log', 'w');
	else $fp = fopen(dirname(__FILE__).'/tunnel_debug.log', 'a');
	$a = date("Y-m-d H:i:s")." ".$txt."\n";
	fwrite($fp, $a);
	fclose($fp);
}

?>