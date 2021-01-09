<?php define('DEV_MODE',0);define('PRODUCT_TYPE','open');include("config.php");if(DEV_MODE==1)error_reporting(E_ALL);else {error_reporting(0);ini_set('error_log',NULL);ini_set('log_errors',0);}ini_set('post_max_size','256M');ini_set('upload_max_filesize','256M');if(intval(DONT_CHANGE_PHP_VALUES)==0){ini_set('max_execution_time',7200);set_time_limit(7200);}define('SCRIPT_VERSION','3.7');define('SCRIPT_FOLDER','webanalyze');$config=array();$config['ENABLE_COMMON_FILTER']=ENABLE_COMMON_FILTER;if($config['ENABLE_COMMON_FILTER']=='ENABLE_COMMON_FILTER')$config['ENABLE_COMMON_FILTER']=1;$config['ENABLE_COMMON_FILTER']=intval($config['ENABLE_COMMON_FILTER']);if(defined('DISABLE_MD5')===false)define("DISABLE_MD5",0);if(defined('SAVE_DEBUG')===false)define("SAVE_DEBUG",0);if(defined('SCAN_METHOD')===false)define("SCAN_METHOD","new");if(strtoupper(substr(PHP_OS,0,3))==='WIN')define(DIRSEP,"\\");else define(DIRSEP,"/");$scan_path=getcwd();$scan_path=substr($scan_path,0,strrpos($scan_path,DIRSEP));define('SCAN_PATH',$scan_path);define('MAIN_WEBSITE','https://www.siteguarding.com/index.php');define('ERR_WRONG_ACCKEY','Wrong access key');if(isset($CONFIG_EXCLUDE_FOLDERS)&&count($CONFIG_EXCLUDE_FOLDERS)>0){foreach($CONFIG_EXCLUDE_FOLDERS as $ex_folder){$ex_folder=SCAN_PATH.trim($ex_folder);$config['EXCLUDE_FOLDERS'][]=str_replace(DIRSEP.DIRSEP,DIRSEP,$ex_folder);}}else $config['EXCLUDE_FOLDERS']=array();$task=trim($_REQUEST['task']);$key=trim($_REQUEST['key']);$key_id=intval($_REQUEST['key_id']);if(SAVE_DEBUG==1)SaveLog('Start: '.$task,true);if(SAVE_DEBUG==1)SaveLog('OS info: '.PHP_OS.' ('.php_uname().')');function SecurityMonitorFinished(){if(SAVE_DEBUG==1)SaveLog('Script terminated');}register_shutdown_function('SecurityMonitorFinished');switch($task){case 'access_id':$a=time();$version=explode('.',PHP_VERSION);$msg=array('ver'=>SCRIPT_VERSION,'md5'=>MD5_OwnSelft(),'time'=>$a,'key'=>md5(SCRIPT_VERSION.MD5_OwnSelft().$a),'os'=>PHP_OS,'php'=>$version[0].'.'.$version[1],'product_type'=>PRODUCT_TYPE);PrintResultOutput($msg,true);if(SAVE_DEBUG==1)SaveLog('Info: '.print_r($msg,true));break;case 'collectdata':if(CheckAccessKey($key)){if(SCAN_METHOD=='old')CollectData($key_id,$config);else CollectData_new($key_id,$config);$plugin_filename=SCAN_PATH.DIRSEP.SCRIPT_FOLDER.DIRSEP.'collectdata.plugins.php';if(file_exists($plugin_filename)){include_once($plugin_filename);if(function_exists('RunPlugins'))RunPlugins();}}else PrintResultOutput(ERR_WRONG_ACCKEY,false);break;case 'runplugins':if(CheckAccessKey($key)){$plugin_filename=SCAN_PATH.DIRSEP.SCRIPT_FOLDER.DIRSEP.'collectdata.plugins.php';if(file_exists($plugin_filename)){include_once($plugin_filename);if(function_exists('RunPlugins'))RunPlugins();}}else PrintResultOutput(ERR_WRONG_ACCKEY,false);break;case 'script_update':if(CheckAccessKey($key))ScriptUpdate();else {PrintResultOutput(ERR_WRONG_ACCKEY,false);}break;case 'get_files':if(CheckAccessKey($key))GetFiles(trim($_REQUEST['file_list']));else {PrintResultOutput(ERR_WRONG_ACCKEY,false);}break;case 'save_files':if(CheckAccessKey($key))SaveFiles();else {PrintResultOutput(ERR_WRONG_ACCKEY,false);}break;default:PrintResultOutput('Wrong task: '.$task,false);break;}if(SAVE_DEBUG==1)SaveLog('Finish: '.$task);exit;function GetFiles($file_list){$a=explode("\n",$file_list);$file_list_array=array();foreach($a as $value){$tmp=trim($value);if(strlen($tmp)>0)$file_list_array[]=$tmp;}echo '<p><b>Uploading started</b></p>';foreach($file_list_array as $file){if(UploadSingleFile($file))echo $file.' - Uploaded successfully'."<br>";else echo '<font color="red">'.$file.' - Upload failed'.'</font>'."<br>";}echo '<p><b>Uploading finished</b></p>';exit;}function ScriptUpdate(){global $_FILES;$destination=getcwd().DIRSEP."collectdata.php";if(!move_uploaded_file($_FILES['file_contents']['tmp_name'],$destination))echo 'Error update: cant move/save uploaded file';}function SaveFiles(){global $_FILES,$_REQUEST;$destination=getcwd().DIRSEP.$_REQUEST['file_name'];if(!move_uploaded_file($_FILES['file_contents']['tmp_name'],$destination))echo 'Error update: cant move/save uploaded file';}function CheckAccessKey($key){if(DEV_MODE==1)return true;for($i=time()-20;$i<=time();$i++){if(md5($i.WEBSITE_KEY)==$key)return true;}return false;}function AnalyzeFile($item,$log_filename){$item_short=str_replace(SCAN_PATH,"",$item);$flag_skip=false;if(strpos($item,$log_filename)!==false)$flag_skip=true;if(!$flag_skip){$file_size=filesize($item);$file_change_date=filectime($item);$file_ext=strtolower(substr($item_short,strrpos($item_short,".")));$md5_file='';if(intval(DISABLE_MD5)==1)$md5_file="|0";else {switch($file_ext){case '.asp':case '.aspx':case '.axd':case '.asx':case '.asmx':case '.ashx':case '.cfm':case '.yaws':case '.swf':case '.jsp':case '.jspx':case '.wss':case '.do':case '.action':case '.pl':case '.php':case '.php4':case '.php3':case '.php5':case '.phtml':case '.py':case '.rb':case '.rhtml':case '.cgi':case '.dll':$md5_file="|".md5_file($item);}}}return array('item_short'=>$item_short,'flag_skip'=>$flag_skip,'file_size'=>$file_size,'file_change_date'=>$file_change_date,'file_ext'=>$file_ext,'md5_file'=>$md5_file);}function CollectData_new($key_id,$config=array(),$gzip=true){if(DEV_MODE==1)$gzip=false;$log_filename=md5($key_id.WEBSITE_ID.date("Ymd")).'.log';if($gzip)$log_filename=$log_filename.".gz";if($gzip)$fp=gzopen($log_filename,'w9');else $fp=fopen($log_filename,'w');if($gzip)gzwrite($fp,"START|".$log_filename."\n");else fwrite($fp,"START|".$log_filename."\n");if(SAVE_DEBUG==1)SaveLog('Scan dir: '.SCAN_PATH);if(SAVE_DEBUG==1)SaveLog('Log file: '.$log_filename);$scanner=new SiteGuarding_files();$scanner->scan_path=SCAN_PATH;$files=$scanner->GetFileList($config['EXCLUDE_FOLDERS']);$counter=0;foreach($files as $item){extract(AnalyzeFile($item,$log_filename));$line=$item_short.'|'.$file_size.'|'.$file_change_date.$md5_file;if(!$flag_skip){$line=str_replace("..\\","/",$line);$line=str_replace("\\","/",$line);if($gzip)gzwrite($fp,$line."\n");else fwrite($fp,$line."\n");$counter++;}}if($gzip)gzwrite($fp,"END|".$log_filename."|".$counter."\n");else fwrite($fp,"END|".$log_filename."|".$counter."\n");if($gzip)gzclose($fp);else fclose($fp);if(!$gzip){if(SAVE_DEBUG==1)SaveLog('Finish');exit;}if(SAVE_DEBUG==1)SaveLog('Start upload to SiteGuarding.com');UploadFile(getcwd().DIRSEP.$log_filename,$key_id,'upload_scan_dump');if(SAVE_DEBUG==1)SaveLog('Finished upload');unlink(getcwd().DIRSEP.$log_filename);if(SAVE_DEBUG==1)SaveLog('Log file removed');}function CollectData($key_id,$config,$gzip=true){if(DEV_MODE==1)$gzip=false;$log_filename=md5($key_id.WEBSITE_ID.date("Ymd")).'.log';if($gzip)$log_filename=$log_filename.".gz";if($gzip)$fp=gzopen($log_filename,'w9');else $fp=fopen($log_filename,'w');if($gzip)gzwrite($fp,"START|".$log_filename."\n");else fwrite($fp,"START|".$log_filename."\n");if(SAVE_DEBUG==1)SaveLog('Scan dir: '.SCAN_PATH);if(SAVE_DEBUG==1)SaveLog('Log file: '.$log_filename);$counter=0;$path=array();if(strtoupper(substr(PHP_OS,0,3))==='WIN')$path[]="..".DIRSEP."*";else $path[]=SCAN_PATH.DIRSEP."*";while(count($path)!=0){$v=array_shift($path);foreach(glob($v) as $item){if(is_dir($item)){if(count($config['EXCLUDE_FOLDERS'])>0){if(!in_array($item.DIRSEP,$config['EXCLUDE_FOLDERS'])){$path[]=$item.DIRSEP.'*';if(SAVE_DEBUG==1)SaveLog('+++ '.$item.DIRSEP);}else if(SAVE_DEBUG==1)SaveLog('--- '.$item.DIRSEP);}else {$path[]=$item.DIRSEP.'*';if(SAVE_DEBUG==1)SaveLog('+++ '.$item.DIRSEP);}}elseif(is_file($item)){extract(AnalyzeFile($item,$log_filename));if($flag_skip!==true){$line=$item_short.'|'.$file_size.'|'.$file_change_date.$md5_file;$flag_skip=false;if(!$flag_skip){$line=str_replace("..\\","/",$line);$line=str_replace("\\","/",$line);if($gzip)gzwrite($fp,$line."\n");else fwrite($fp,$line."\n");$counter++;}}}}$v=str_replace("*",".*",$v);foreach(glob($v) as $item){if(is_dir($item)){$tmp=explode(DIRSEP,$item);$tmp=end($tmp);if($tmp!='.'&&$tmp!='..')$path[]=$item.DIRSEP.'*';}elseif(is_file($item)){extract(AnalyzeFile($item,$log_filename));$line=$item_short.'|'.$file_size.'|'.$file_change_date.$md5_file;$flag_skip=false;if(!$flag_skip){$line=str_replace("..\\","/",$line);$line=str_replace("\\","/",$line);if($gzip)gzwrite($fp,$line."\n");else fwrite($fp,$line."\n");$counter++;}}}}if($gzip)gzwrite($fp,"END|".$log_filename."|".$counter."\n");else fwrite($fp,"END|".$log_filename."|".$counter."\n");if($gzip)gzclose($fp);else fclose($fp);if(!$gzip){if(SAVE_DEBUG==1)SaveLog('Finish');exit;}if(SAVE_DEBUG==1)SaveLog('Start upload to SiteGuarding.com');UploadFile(getcwd().DIRSEP.$log_filename,$key_id,'upload_scan_dump');if(SAVE_DEBUG==1)SaveLog('Finished upload');unlink(getcwd().DIRSEP.$log_filename);if(SAVE_DEBUG==1)SaveLog('Log file removed');}function UploadFile($file,$key_id,$task){$target_url=MAIN_WEBSITE;$file_name_with_full_path=$file;$post=array('task'=>$task,'option'=>'com_securapp','key_id'=>$key_id,'file_contents'=>'@'.$file_name_with_full_path);$ch=curl_init();curl_setopt($ch,CURLOPT_URL,$target_url);curl_setopt($ch,CURLOPT_POST,1);curl_setopt($ch,CURLOPT_SAFE_UPLOAD,false);curl_setopt($ch,CURLOPT_POSTFIELDS,$post);curl_setopt($ch,CURLOPT_INFILE,$file_name_with_full_path);curl_setopt($ch,CURLOPT_INFILESIZE,filesize($file_name_with_full_path));curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,false);curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);$result=curl_exec($ch);$curl_error=curl_error($ch);curl_close($ch);if(!$result){if(SAVE_DEBUG==1)SaveLog('CURL upload is failed - '.$curl_error);}}function UploadSingleFile($file){$target_url=MAIN_WEBSITE;$file_name_with_full_path=SCAN_PATH.DIRSEP.$file;$post=array('task'=>'UploadSingleFile','option'=>'com_securapp','website_id'=>WEBSITE_ID,'website_tmp_access'=>md5(WEBSITE_ID.WEBSITE_KEY),'file_contents'=>'@'.$file_name_with_full_path);$ch=curl_init();curl_setopt($ch,CURLOPT_URL,$target_url);curl_setopt($ch,CURLOPT_POST,1);curl_setopt($ch,CURLOPT_SAFE_UPLOAD,false);curl_setopt($ch,CURLOPT_POSTFIELDS,$post);curl_setopt($ch,CURLOPT_INFILE,$file_name_with_full_path);curl_setopt($ch,CURLOPT_INFILESIZE,filesize($file_name_with_full_path));curl_setopt($ch,CURLOPT_SSL_VERIFYHOST,false);curl_setopt($ch,CURLOPT_SSL_VERIFYPEER,false);$result=curl_exec($ch);$curl_error=curl_error($ch);curl_close($ch);if($curl_error)return false;else return true;}function MD5_OwnSelft(){return md5_file(SCAN_PATH.DIRSEP.SCRIPT_FOLDER.DIRSEP.'collectdata.php');}function PrintResultOutput($msg,$type=false){if($type){$a=array('status'=>'success','msg'=>$msg);}else {$a=array('status'=>'error','msg'=>$msg);}echo json_encode($a);}function CheckShellCommands(){if(function_exists('exec'))return true;else return false;}function SaveLog($txt,$flag_new=false){if($flag_new)$fp=fopen(getcwd().DIRSEP."debug.log",'w');else $fp=fopen(getcwd().DIRSEP."debug.log",'a');fwrite($fp,$txt."\n");fclose($fp);}class SiteGuarding_files{ public static $debug=false;var $scan_path='';var $exclude_folders_real=array(); public function GetFileList($exclude_folders=array()){if(strtoupper(substr(PHP_OS,0,3))==='WIN')define(DIRSEP,'\\');else define(DIRSEP,'/');$scan_path=$this->scan_path;$this->exclude_folders_real=$exclude_folders;$files_list=array();$dirList=array();$dirList[]=$scan_path;while(true){$dirList=array_merge(self::ScanFolder(array_shift($dirList),$files_list),$dirList);if(count($dirList)<1)break;}return $files_list;}function ScanFolder($path,&$files_list){$dirList=array();if($currentDir=opendir($path)){while($file=readdir($currentDir)){if($file==='.'||$file==='..'||is_link($path))continue;$file=$path.'/'.$file;if(is_dir($file)){$folder=$file.DIRSEP;$folder=str_replace(DIRSEP.DIRSEP,DIRSEP,$folder);if(count($this->exclude_folders_real)){if(in_array($folder,$this->exclude_folders_real)){continue;}}$dirList[]=$file;}else {$files_list[]=$file;}}closedir($currentDir);}return $dirList;}}?>