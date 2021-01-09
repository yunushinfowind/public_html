<?php
/**
 * Class Firewall
 */

class SiteGuarding_Firewall
{
    var $rules = array();

    var $scan_path = '';
    var $save_empty_requests = false;
    var $single_log_file = false;
    var $dirsep = '/';
    var $email_for_alerts = '';
    var $this_session_rule = false;
    var $this_session_reason_to_block = '';
    var $float_file_folder = false;


	public function LoadRules()
	{
        $rules = array(
            'ALLOW_ALL_IP' => array(),
            'BLOCK_ALL_IP' => array(),
            'ALERT_IP' => array(),
            'BLOCK_RULES_IP' => array(),
            'RULES' => array(
                'ALLOW' => array(),
                'BLOCK' => array()
            ),
            'BLOCK_RULES' => array(
                'ALLOW' => array(),
                'BLOCK' => array()
            ),
            'BLOCK_REQUESTS' => array()
        );
        $this->rules = $rules;

        $rows = file(dirname(__FILE__).$this->dirsep.'rules.txt', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if (count($rows) == 0) return true;


        $section = '';
        foreach ($rows as $row)
        {
            $row = trim($row);
            if ($row == '::ALLOW_ALL_IP::') {$section = 'ALLOW_ALL_IP'; continue;}
            if ($row == '::BLOCK_ALL_IP::') {$section = 'BLOCK_ALL_IP'; continue;}
            if ($row == '::ALERT_IP::') {$section = 'ALERT_IP'; continue;}
            if ($row == '::BLOCK_RULES_IP::') {$section = 'BLOCK_RULES_IP'; continue;}
            if ($row == '::RULES::') {$section = 'RULES'; continue;}
            if ($row == '::BLOCK_RULES::') {$section = 'BLOCK_RULES'; continue;}
            if ($row == '::BLOCK_REQUESTS::') {$section = 'BLOCK_REQUESTS'; continue;}

            if ($row[0] == '#' || $section == '') continue;

            switch ($section)
            {
                case 'BLOCK_REQUESTS':
                    $tmp = explode("|", $row);
                    $rule_field = trim($tmp[0]);
                    $rule_value = trim($tmp[1]);
                    $rules['BLOCK_REQUESTS'][$rule_field][] = $rule_value;
                    break;

                case 'ALLOW_ALL_IP':
                case 'BLOCK_ALL_IP':
                case 'ALERT_IP':
                case 'BLOCK_RULES_IP':
                    $rules[$section][] = str_replace(array(".*.*.*", ".*.*", ".*"), ".", trim($row));
                    break;

                case 'RULES':
                case 'BLOCK_RULES':
                    $tmp = explode("|", $row);
                    $rule_kind = strtolower(trim($tmp[0]));
                    $rule_type = strtolower(trim($tmp[1]));
                    $rule_object = str_replace($this->dirsep.$this->dirsep, $this->dirsep, $this->scan_path.trim($tmp[2]));

                    switch ($rule_kind)
                    {
                        case 'allow':
                            $rules[$section]['ALLOW'][] = array('type' => $rule_type, 'object' => $rule_object);
                            break;

                        case 'block':
                            $rules[$section]['BLOCK'][] = array('type' => $rule_type, 'object' => $rule_object);
                            break;
                    }

                    break;

                default:
                    continue;
                    break;
            }
        }

        $this->rules = $rules;

        return true;
    }



    public function Session_Apply_Rules($file)
    {
        $result_final = '';

        if (count($this->rules['RULES']['BLOCK']))
        {
            foreach ($this->rules['RULES']['BLOCK'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                if ($this->float_file_folder === true) $pattern = dirname($file).$this->dirsep.$pattern;

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'block';
            }
        }

        if (count($this->rules['RULES']['ALLOW']))
        {
            foreach ($this->rules['RULES']['ALLOW'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                if ($this->float_file_folder === true) $pattern = dirname($file).$this->dirsep.$pattern;

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'allow';
            }
        }

        return $result_final;
    }




    public function Session_Apply_BLOCK_RULES_IP($file, $ip)
    {
        $result_final = '';

        if (count($this->rules['BLOCK_RULES_IP']) == 0) return $result_final;

        foreach ($this->rules['BLOCK_RULES_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                break;
            }
        }


        if (count($this->rules['BLOCK_RULES']['BLOCK']))
        {
            foreach ($this->rules['BLOCK_RULES']['BLOCK'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'block';
            }
        }

        if (count($this->rules['BLOCK_RULES']['ALLOW']))
        {
            foreach ($this->rules['BLOCK_RULES']['ALLOW'] as $rule_info)
            {
                $type = $rule_info['type'];
                $pattern = $rule_info['object'];

                switch ($type)
                {
                    case 'any':
                        $pattern .= '*';
                    default:
                    case 'file':
                        $result = fnmatch($pattern, $file);
                        break;

                    case 'folder':
                        $pattern .= '*';
                        $result = fnmatch($pattern, $file, FNM_PATHNAME);
                        break;
                }

                if ($result === true) $result_final = 'allow';
            }
        }

        return $result_final;
    }




    public function Session_Check_Requests($requests)
    {
        $result_final = 'allow';

        if (count($requests) == 0) return $result_final;
        
        $requests_flat = self::FlatRequestArray($requests);

        //foreach ($requests_flat as $req_field => $req_value)
        foreach ($requests_flat as $requests_flat_array)
        {
            $req_field = $requests_flat_array['f'];
            $req_value = $requests_flat_array['v'];
            
            if (isset($this->rules['BLOCK_REQUESTS'][$req_field]))
            {
                foreach ($this->rules['BLOCK_REQUESTS'][$req_field] as $rule_values)
                {
                    if ($rule_values == '*')
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $req_field.":*";
                        return $result_final;
                    }

                    if (strpos($req_value, $rule_values) !== false)
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = $req_field.":".$rule_values;
                        return $result_final;
                    }
                }
            }

            if (isset($this->rules['BLOCK_REQUESTS']['*']))
            {
                foreach ($this->rules['BLOCK_REQUESTS']['*'] as $rule_values)
                {
                    if ($rule_values == '*')
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = "*:*";
                        return $result_final;
                    }

                    if (strpos($req_value, $rule_values) !== false)
                    {
                        $result_final = 'block';
                        $this->this_session_reason_to_block = "*:".$rule_values;
                        return $result_final;
                    }
                }
            }
        }

        return $result_final;
    }


    public function FlatRequestArray($requests)
    {
        $a = array();
        
        foreach ($requests as $f => $v)
        {
            if (is_array($v))
            {
                $a[] = array('f' => $f, 'v' => '');
                
                foreach ($v as $f2 => $v2)
                {
                    if (is_array($v2))
                    {
                        $a[] = array('f' => $f2, 'v' => '');
                        
                        foreach ($v2 as $f3 =>$v3)
                        {
                            if (is_array($v3)) $v3 = json_encode($v3);
                            $a[] = array('f' => $f3, 'v' => $v3);
                        }
                    }
                    else $a[] = array('f' => $f2, 'v' => $v2); 
                }
            }
            else {
                $a[] = array('f' => $f, 'v' => $v);
            }
        }    
        
        return $a;
    }
    
    


    public function Block_This_Session($reason = '', $save_request = false)
    {
        $log_txt = 'Blocked '.$_SERVER["REMOTE_ADDR"].' File: '.$_SERVER['SCRIPT_FILENAME'];
        if ($reason != '') $log_txt .= ' Reason: '.$reason;
        if ($save_request === true) $log_txt .= ' Request: '.print_r($_REQUEST, true)."\n\n";
        $this->SaveLogs($log_txt);
        die('Access is not allowed. Please contact website webmaster or SiteGuarding.com support');
    }




    public function CheckIP_in_Allowed($ip)
    {
        if (count($this->rules['ALLOW_ALL_IP']) == 0) return false;

        foreach ($this->rules['ALLOW_ALL_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                return true;
            }
        }
    }



    public function CheckIP_in_Blocked($ip)
    {
        if (count($this->rules['BLOCK_ALL_IP']) == 0) return false;

        foreach ($this->rules['BLOCK_ALL_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                return true;
            }
        }
    }



    public function CheckIP_in_Alert($ip)
    {
        if (count($this->rules['ALERT_IP']) == 0) return false;

        foreach ($this->rules['ALERT_IP'] as $rule_ip)
        {
            if (strpos($ip, $rule_ip) === 0) {
                // match
                return true;
            }
        }
    }



	public function LogRequest($mark_as_blocked = false)
	{
        if (!$this->save_empty_requests && count($_REQUEST) == 0) return;

        if ($this->single_log_file) $siteguargin_log_file = '_logs.php';
        else {
        	$siteguargin_log_file = basename($_SERVER['SCRIPT_FILENAME'])."_".md5($_SERVER['SCRIPT_FILENAME']).".php";
        }
        $siteguargin_log_file = dirname(__FILE__).$this->dirsep.'logs'.$this->dirsep.$siteguargin_log_file;
        if (!file_exists($siteguargin_log_file)) $siteguargin_log_file_new = true;
        else $siteguargin_log_file_new = false;

        $siteguarding_fp = fopen($siteguargin_log_file, "a");

        if ($mark_as_blocked)
        {
            $siteguarding_log_line = date("Y-m-d H:i:s").' Request above is BLOCKED.'."\n\n\n\n";
        }
        else {
            $siteguarding_log_line = date("Y-m-d H:i:s")."\n".
            	"IP:".$_SERVER["REMOTE_ADDR"]."\n".
            	"Link:"."http://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]"."\n".
            	"File:".$_SERVER['SCRIPT_FILENAME']."\n".
            	print_r($_REQUEST, true)."\n\n";
        }

        if ($siteguargin_log_file_new) fwrite($siteguarding_fp, '<?php exit; ?>'."\n".$_SERVER['SCRIPT_FILENAME']."\n\n");
        fwrite($siteguarding_fp, $siteguarding_log_line);
        fclose($siteguarding_fp);
    }


	public function SaveLogs($txt)
	{
    	$log_file = dirname(__FILE__).$this->dirsep.'logs'.$this->dirsep.'_blocked.log';

    	if (file_exists($log_file) && filesize($log_file) > .5 * 1024 * 1024)
    	{
    		$log_array = file($log_file);
    		$offset = count($log_array) - 300;
    		$log_array = array_splice($log_array, $offset, 300);

    		$fp = fopen($log_file, 'w');
    		fwrite($fp, implode("\n", $log_array)."\n");
    	}
    	else $fp = fopen($log_file, 'a');

    	$a = date("Y-m-d H:i:s")." ".$txt."\n";
    	fwrite($fp, $a);
    	fclose($fp);
    }


	public function SendEmail($subject, $message)
	{
        $to      = $this->email_for_alerts;
        if ($to == '') return;

        $headers = 'From: '. $to . "\r\n";

        mail($to, $subject, $message, $headers);
    }


    public function InstallPHPini()
    {
        $lock_file = dirname(__FILE__).$this->dirsep.'logs'.$this->dirsep.'phpini.lock';
        if (!file_exists($lock_file) || date("Y-m-d", filectime($lock_file)) < date("Y-m-d"))
        {
            // Install php.ini
            $exclude_folders = array('/webanalyze/');
            $a = new SGAntiVirus_scanner();
            $dir_list = $a->scan($this->scan_path, $exclude_folders);
            $dir_list[] = $this->scan_path;

            $fp = fopen($lock_file, 'w');
            fwrite($fp, date("Y-m-d"));
            fclose($fp);


            // Add php.ini files
            foreach ($dir_list as $dir_path)
            {
                $file_phpini = $dir_path.'php.ini';
                //echo $file_phpini."<br>";
                if (file_exists($file_phpini))
                {
                    echo $file_phpini."<br>";
                }
                else {
                    $fp = fopen($file_phpini, 'w');
                    fwrite($fp, $phpini_code);
                    fclose($fp);

                    $i++;
                }
            }
        }
    }

}


class SGAntiVirus_scanner
{
    var $exclude_folders_real = array();




    function scan($scan_path, $exclude_folders)
    {
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

        $files_list = array();
        $dirList = array();
        $dirList[] = $scan_path;

        // Scan all dirs
        while (true)
        {
            $dirList = array_merge(self::ScanFolder(array_shift($dirList), $files_list), $dirList);
            if (count($dirList) < 1) break;
        }

        return $files_list;
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
        				    //echo '--- '.$folder."<br>";
                            continue;
        				}
        				//else echo '+++ '.$folder."<br>";
                    }
                    //else echo $file."<br>";
                    $dirList[] = $file;
                    $files_list[] = $folder;

                }


            }
            closedir($currentDir);
        }

        return $dirList;
    }



}
?>