<?php

/*
Version 0.1
Last Modified: November 12 2013
Author: Carlos Moreira
*/

if ( !class_exists('cmshowcase_shortcode' ) ) {
    class cmshowcase_shortcode {

    	private $showcase_id;
        private $shortcodes;
        private $generator;
        public  $layouts;

        public $title;
        public $menu_title;
        public $menu_capability;
        public $description;


        function __construct($id,$shortcodes,$layouts) {

            //we star by setting the global variables
            $this->showcase_id = $id;      
            $this->generator = $shortcodes['generator'];

            // Build Layouts object array
            $this->add_layouts($layouts);


            /*
            if(isset($shortcodes['shortcodes'])){
                $this->shortcodes = $shortcodes['shortcodes'];
                $this->add_new_shortcode($shortcodes['shortcodes']);
            }
            */
            
            
            if(isset($shortcodes['generator'])) {

                $this->add_new_generator($shortcodes['generator']);

                //add the preview function
                add_action( 'wp_ajax_cmshowcase', array($this,'generator_ajax_function'));
                add_action( 'wp_ajax_cmshowcase_save_shortcode', array($this,'generator_ajax_function'));
                add_action( 'wp_ajax_cmshowcase_view_shortcodes', array($this,'generator_ajax_function'));
                add_action( 'wp_ajax_cmshowcase_load_shortcode', array($this,'generator_ajax_function'));
                add_action( 'wp_ajax_cmshowcase_delete_shortcode', array($this,'generator_ajax_function'));

                

                //add the shortcodes
                if(isset($shortcodes['generator']['generators'])) {
                    $this->shortcodes = $shortcodes['generator']['generators'];
                    $this->add_new_shortcode($shortcodes['shortcodes']);
                }
            }

            /*
            In case we include the layouts in the shortcodes array
            if(isset($shortcodes['layouts'])){

                $this->add_layouts($shortcodes['layouts']);

            }
            */

        }

        public function generator_ajax_function() {


                    $update_shortcodes = false;
                    $unique = true;

                    if($_POST['action'] == 'cmshowcase_load_shortcode') {


                        $saved_shortcodes = get_option($this->showcase_id.'_saved_shortcodes',array());
                        $name = stripslashes($_POST['name']);
                        $generator = $_POST['generator'];

                        if(isset($saved_shortcodes[$generator][$name])) {
                            echo $saved_shortcodes[$generator][$name];
                        }

                        die(); 

                    }

                    if($_POST['action'] == 'cmshowcase_delete_shortcode') {

                        $update_shortcodes = true;
                         // needed variables
                        $name = stripslashes($_POST['name']);
                        $generator = $_POST['generator'];

                        $saved_shortcodes = get_option($this->showcase_id.'_saved_shortcodes',array());

                        if(isset($saved_shortcodes[$generator][$name])) {
                            unset($saved_shortcodes[$generator][$name]);
                        }

                        $new_saved_shortcodes = update_option($this->showcase_id.'_saved_shortcodes',$saved_shortcodes);

                    }
                    
                    if($_POST['action'] == 'cmshowcase_save_shortcode') {

                        $update_shortcodes = true;
                         // needed variables
                        $shortcode = stripslashes($_POST['shortcode']);
                        $name = stripslashes($_POST['name']);
                        $generator = $_POST['generator'];
                        $override = $_POST['override_name'];

                        $saved_shortcodes = get_option($this->showcase_id.'_saved_shortcodes',array());

                        if($override!='null') {

                            $saved_shortcodes[$generator][$override] = $shortcode; 
                            $new_saved_shortcodes = update_option($this->showcase_id.'_saved_shortcodes',$saved_shortcodes);

                        } else {

                             //check if alias already exists
                            if(isset($saved_shortcodes[$generator])) {

                                foreach ($saved_shortcodes[$generator] as $s_name => $s_short) {

                                    if($s_name == $name) {
                                        $unique = false;
                                    }

                                }
                            }
                            //print_r($saved_shortcodes);

                            //only adds new value if alias is unique
                           if($unique) {

                                $saved_shortcodes[$generator][$name] = $shortcode; 
                                $new_saved_shortcodes = update_option($this->showcase_id.'_saved_shortcodes',$saved_shortcodes);

                           }


                        }
                       

                        

                    }

                    if($_POST['action'] == 'cmshowcase_view_shortcodes' || $update_shortcodes) {

                        $generator = $_POST['generator'];
                        $trigger = $_POST['shortcode_trigger'];

                        $saved_shortcodes = get_option($this->showcase_id.'_saved_shortcodes','');
                        if(isset($saved_shortcodes[$generator]) && count($saved_shortcodes[$generator]) > 0) {

                            $saved_title = __('Saved Shortcodes',$this->showcase_id);


                            //If visual composer is active
                            if ( defined( 'WPB_VC_VERSION' ) ) {
                                $saved_title .= '<span class="howto">'.__('These will display in the Visual Composer options.',$this->showcase_id).'</span>'; 
                            }

                            $html = '<div class="cmshowcase_saved_title">'. $saved_title.'</div>';
                            $html .= '<table class="cmshowcase_shortcodes_table">';
                            foreach ($saved_shortcodes[$generator] as $s_name => $s_short) {
                                $html .= '<tr><td>'.$s_name.'<td><input class="cmshowcase_alias_input" value="['.$trigger.' alias=&#39;'.$s_name.'&#39;]"></input></td><td><a onclick="cmshowcase_load_shortcode_saved(\''.$generator.'\',\''.$s_name.'\')" class="button">'.__('Load',$this->showcase_id).'</a></td><td><a onclick="cmshowcase_delete_shortcode_saved(\''.$generator.'\',\''.$s_name.'\',\''.__('Are you sure you want to delete this entry?',$this->showcase_id).'\')" class="button">'.__('Delete',$this->showcase_id).'</a></td></tr>';
                            }
                            $html .= '</table>';

                            if(!$unique) {
                                $html = '<div class="cmshowcase_warning">'.__('Alias name already exists. Please use a diferent one',$this->showcase_id).'</div><br>'.$html;
                            }

                            //$html .= '<span class="howto">'.__('You can use the saved shortcodes Alias in your posts, pages and widgets instead of the long descriptive shortcodes.',$this->showcase_id).'</span>';

                            echo $html;
                            
                        }
                        die(); // this is required to return a proper result

                    }

                    if($_POST['action'] == 'cmshowcase') {

                        // to add the preview function
                        $shortcode = stripslashes($_POST['shortcode']);
                        $html = do_shortcode($shortcode);
                        echo $html;  
                        die(); // this is required to return a proper result

                    }

                    

                    
                }

       
        function add_new_generator($opt) {

            $id = $this->showcase_id;

            $this->title = isset($opt['menu_title']) ? $opt['menu_title'] : __('Shortcode Generator',$id);
            $this->menu_title = isset($opt['menu_title']) ? $opt['menu_title'] : __('Shortcode Generator',$id);
            $this->description = isset($opt['description']) ? $opt['description'] : '';
            $this->capability = isset($opt['capability']) ? $opt['capability'] : 'manage_options';
            
            //We add the new menu entry
            add_action( 'admin_menu', array($this,'add_generator_page'));
        }

        function add_generator_page() {

            $id = $this->showcase_id;
            $title = $this->title;
            $menu_title = $this->menu_title;
            $capability = $this->capability;


            $parent_slug = 'edit.php?post_type='.$id;
            $page_title = __($title,$id);
            $menu_title = __($menu_title,$id);
            $capability = $capability;
            $slug = strtolower( str_replace( ' ', '_', $title ) );
            $menu_slug = $id.'_'.$slug;
            $function = array($this, 'generator_page');
            
           add_submenu_page( $parent_slug, $page_title, $menu_title, $capability, $menu_slug, $function );

        }


        function generator_page() {

        $this->enqueue_generator_scripts();

        $generator = $this->generator;


        // Enqueue scripts from layouts

        foreach ($this->layouts as $object) {

            foreach ($object as $layout) {

                if(isset($layout->enqueue_files)) {

                    cmshowcase_enqueue_layout_scripts($layout->enqueue_files);
                
                }  
            
            }

        }

        //Check if custom layouts exist, create object and enqueue files
        $gens_check = $generator['generators'];

        foreach ($gens_check as $gen => $val) { 

            if (isset($val['type']) && $val['type'] == 'custom') {

                if(isset($val['class'])) {

                    $custom_gen[$gen] = new $val['class']($this->showcase_id);

                    $custom = $custom_gen[$gen];
                    
                    if(isset($custom->enqueue_files)) {

                        cmshowcase_enqueue_layout_scripts($custom->enqueue_files);
                
                    }  

                }

            }    

        }


        echo '<div id="icon-edit" class="icon32 icon32-posts-'.$this->showcase_id.'"><br></div>';
        echo "<h2>". __($generator['page_title'],$this->showcase_id) ."</h2>"; 

        if(isset($generator['intro_text'])) {
            echo "<div class='cm_intro_text'>".__($generator['intro_text'],$this->showcase_id)."</div>";
        }

        if(count($generator['generators'])>1) {

            $available_label = isset($generator['pre_nav_label']) ? $generator['pre_nav_label'] : 'Available Generators';

        ?>


        <div id='cm-nav-wrapper'>

             <span class='cm-nav-info'><?php echo __($available_label,$this->showcase_id);?> </span>
                
                <?php 

                 $gens = $generator['generators'];

                 foreach ($gens as $gen => $val) { 

                    $gen_title = isset($val['title']) ? $val['title'] : 'Generator';
                    $gen_id = trim($gen);
                    ?>

                 <span class='cm-nav-tab' id='<?php echo $gen_id; ?>_nav'><a onclick="cmshowcase_show_generator('<?php echo $gen_id; ?>_wrapper')"><?php echo __($gen_title,$this->showcase_id); ?></a></span>

                <?php } ?>

            </div>

        <?php 

        }

        ?>


        <div id="ttwrap">

            


            <?php


            $display = 'block';
            $gen_count = 0;

            foreach ($generator['generators'] as $generator => $values) { 

                $generator_id = trim($generator);
                $generator_title = isset($values['title']) ? $values['title'] : '';
                $generator_description = isset($values['description']) ? $values['description'] : '';
                $query_title = isset($values['labels']['query']) ? $values['labels']['query'] : 'What entries to display';
                $layout_title = isset($values['labels']['layout']) ? $values['labels']['layout'] : 'How to display the entries';
                $shortcode_label = isset($values['labels']['shortcode']) ? $values['labels']['shortcode'] : 'Shortcode';
                $php_label = isset($values['labels']['php']) ? $values['labels']['php'] : 'Get PHP function';
                $load_label = isset($values['labels']['load_shortcode']) ? $values['labels']['load_shortcode'] : 'Place a shortcode here to load it';
                $shortcode_title_label = isset($values['labels']['shortcode_title']) ? $values['labels']['shortcode_title'] : 'Shortcode';
                $preview_title_label = isset($values['labels']['preview_title']) ? $values['labels']['preview_title'] : 'Preview';
                $preview_description_label = isset($values['labels']['preview_description']) ? $values['labels']['preview_description'] : '';
                $preview_light_bg_label = isset($values['labels']['preview_light_bg']) ? $values['labels']['preview_light_bg'] : 'Light Background';
                $preview_dark_bg_label = isset($values['labels']['preview_dark_bg']) ? $values['labels']['preview_dark_bg'] : 'Dark Background';

                $gen_type = isset($values['type']) ? $values['type'] : 'layout';

                ?>


            <div id="<?php echo $generator_id; ?>_wrapper" style="display:<?php echo $display; ?>;">
             
             <?php 
             if($generator_description!='') {
              ?>
                     <div class="cmgenerator_description"><?php echo __($generator_description,$this->showcase_id); ?></div>
            <?php
            }
            ?>
            
                <div class="cmgenerator_left">


                    <div id = "cm_generator_table">
                        <div class='postbox'>
                        <form id="<?php echo $generator_id; ?>">
                            <input type='hidden' id='shortcode' value='<?php echo $values['shortcode']; ?>' />
                            <input type='hidden' id='gen_count' value='<?php echo $gen_count; $gen_count++; ?>' />



                            <table>

                            <?php
                            if( isset( $values['supports'] ) ) {
                            ?>

                            <tr>
                                <td colspan="2"> <h2> <?php echo __($query_title,$this->showcase_id); ?> </h2></td>
                            </tr>
                            <?php
                            

                                $supports = $values['supports'];

                                foreach ($supports as $input => $args) {
                                    //functions are defined in the utils-advanced.php file
                                    call_user_func('cmshowcase_build_shortcode_field_'.$input, $this->showcase_id, $args);

                                }

                            }
                            ?>
                            <?php 
                            if($gen_type=='layout') { 
                            ?>
                                    <tr>
                                    <td colspan="2"><h2>  <?php echo __($layout_title,$this->showcase_id); ?>  </h2></td>
                                </tr>
                                <tr>
                                    <td class="cmshowcase_field_label"><?php echo __('Layouts',$this->showcase_id); ?> </td>
                                    <td>
                                    <?php

                                    $args = array();
                                    $args['id'] = 'layout'; //str_replace($cpt.'_','',$tax->query_var);
                                    $args['default'] = '';
                                    $args['description'] = '';
                                    $args['onchange'] = 'cmshowcase_display_layout_options(this)';
                                    $opt = array();
                                    foreach ($this->layouts as $object) {

                                            foreach ($object as $layout) {
                                                $opt[$layout->layout_id] = $layout->layout_name;
                                            }

                                        }
                                    $args['options'] = cmshowcase_translate_array($opt,$this->showcase_id);

                                    cmshowcase_build_field_select( $args );

                                    ?>

                                    </td>
                                </tr> 
                            <?php 
                            }   

                            if($gen_type=='custom' && isset($values['src']) && isset($values['class'])) { 
                                
                            
                                $customg = $custom_gen[$generator_id];

                                if(isset($customg->options)) {

                                    foreach ($customg->options as $key => $value) {
                                    
                                        if(isset($value['type']) && ($value['type'] == 'seperator' || $value['type'] == 'html'  || $value['type'] == 'html_bold' || $value['type'] == 'hidden' || $value['type'] == 'hidden_html')) {

                                            if(isset($value['type']) && $value['type'] == 'seperator') {

                                            echo '<tr><td colspan="2" class="cmseperator"></td></tr>';

                                            }    

                                            if(isset($value['type']) && $value['type'] == 'html') {

                                            echo '<tr><td colspan="2">'.__($value['label'],$this->showcase_id).'</td></tr>';


                                            }

                                            if(isset($value['type']) && $value['type'] == 'html_bold') {

                                            echo '<tr><td colspan="2"><strong>'.__($value['label'],$this->showcase_id).'</strong></td></tr>';


                                            }

                                            if(isset($value['type']) && $value['type'] == 'hidden') {

                                                $args = array();
                                                $args['generator'] = $generator_id;
                                                $args['id'] = $key;
                                                $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                                $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                                $args['value'] = isset( $value['value'] ) ? $value['value'] : $default;

                                                call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                            } 

                                            if(isset($value['type']) && $value['type'] == 'hidden_html') {

                                                $args = array();
                                                $args['generator'] = $generator_id;
                                                $args['id'] = $key;
                                                $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                                $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                                $args['value'] = isset( $value['value'] ) ? $value['value'] : $default;

                                                call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                            } 


                                        }



                                        else {
                                        
                                            ?>


                                            <tr>
                                                <td>
                                                <?php echo __($value['label'],$this->showcase_id); ?>
                                                </td>
                                                <td>
                                                <?php

                                                
                                                $args = array();
                                                $args['generator'] = $generator_id;
                                                $args['id'] = $key;
                                                $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                                $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                                $args['description'] = isset( $value['description'] ) ? __($value['description'],$this->showcase_id) : '';
                                                $args['options'] = isset( $value['options'] ) ? cmshowcase_translate_array($value['options'],$this->showcase_id) : null;
                                                $args['size'] = isset( $value['size'] ) ? $value['size'] : null;
                                                $args['onchange'] = "cmshowcase_build_shortcode('".$generator_id."')";

                                                $args['extra_options'] = isset( $value['extra_options'] ) ? $value['extra_options'] : false;

                                                //for taxonomies
                                                $args['cpt'] = $this->showcase_id;
                                                $args['none_label'] = isset( $value['none_label'] ) ? $value['none_label'] : 'None';

                                                call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                                ?>
                                                </td>
                                            </tr>

                                            <?php
                                        }

                                }

                                }

                            
                            }

                            ?>              

                        </table>
                        </form>

                                

                        <div id="<?php echo $generator_id; ?>_layout_options">

                        <?php

                        foreach ($this->layouts as $object) {    

                                foreach ($object as $layout) {

                        ?>
                

                        
                            <form id="<?php echo $generator_id; ?>_<?php echo $layout->layout_id; ?>" style="display:none;">

                                <input type='hidden' id='generatorid' value='<?php echo $generator_id; ?>' />

                                <?php
                                $cal = isset($layout->shortcode_check) ? $layout->shortcode_check : '';
                                ?>

                                <input type='hidden' id='layoutcallback' value='<?php echo $cal; ?>' />
                                
                            <table>

                            <?php
                            if(isset($layout->options)) {

                                
                                foreach ($layout->options as $key => $value) {
                                    
                                    if(isset($value['type']) && ($value['type'] == 'seperator' || $value['type'] == 'html' || $value['type'] == 'html_bold' || $value['type'] == 'hidden' || $value['type'] == 'hidden_html')) {

                                            if(isset($value['type']) && $value['type'] == 'seperator') {

                                            echo '<tr><td colspan="2" class="cmseperator"></td></tr>';

                                            }    

                                            if(isset($value['type']) && $value['type'] == 'html') {

                                            echo '<tr><td colspan="2">'.__($value['label'],$this->showcase_id).'</td></tr>';


                                            }

                                             if(isset($value['type']) && $value['type'] == 'html_bold') {

                                            echo '<tr><td colspan="2"><strong>'.__($value['label'],$this->showcase_id).'<strong></td></tr>';


                                            }

                                            if(isset($value['type']) && $value['type'] == 'hidden') {

                                                $args = array();
                                                $args['generator'] = $generator_id;
                                                $args['id'] = $key;
                                                $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                                $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                                $args['value'] = isset( $value['value'] ) ? $value['value'] : $default;

                                                call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                            } 

                                             if(isset($value['type']) && $value['type'] == 'hidden_html') {

                                                $args = array();
                                                $args['generator'] = $generator_id;
                                                $args['id'] = $key;
                                                $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                                $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                                $args['value'] = isset( $value['value'] ) ? $value['value'] : $default;

                                                call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                            } 


                                        }

                                    else {
                                    
                                        ?>


                                        <tr>
                                            <td>
                                            <?php echo __($value['label'],$this->showcase_id); ?>
                                            </td>
                                            <td>
                                            <?php

                                            
                                            $args = array();
                                            $args['generator'] = $generator_id;
                                            $args['id'] = $key;
                                            $args['type'] = isset( $value['type'] ) ? $value['type'] : 'text';
                                            $args['default'] = isset( $value['default'] ) ? $value['default'] : '';
                                            $args['description'] = isset( $value['description'] ) ? __($value['description'],$this->showcase_id) : '';
                                            $args['options'] = isset( $value['options'] ) ? cmshowcase_translate_array($value['options'],$this->showcase_id) : null;
                                            $args['size'] = isset( $value['size'] ) ? $value['size'] : null;
                                            $args['onchange'] = "cmshowcase_build_shortcode('".$generator_id."')";

                                            call_user_func('cmshowcase_build_field_'.$args['type'], $args);

                                            ?>
                                            </td>
                                        </tr>

                                        <?php
                                    }

                                }

                            }
                            ?>
                            </table>
                        </form>
                    
                <?php
                            
                        }

                    }

                ?>

                </div>

                </div>
                </div>

                </div>
                <div id="cmmainpreview">

                    <div class='cmbreed'>

                    <h2><?php echo __($shortcode_title_label,$this->showcase_id); ?></h2>

                    <ul id="cm_shortcode_nav">
                        <li class="cm_shortcode_nav_current" id="<?php echo $generator_id; ?>_shortcode_sc" onclick="cmshowcase_shortcode('<?php echo $generator_id; ?>',this)">Shortcode</li>
                        <li id="<?php echo $generator_id; ?>_shortcode_php" onclick="cmshowcase_shortcode_php('<?php echo $generator_id; ?>',this)">PHP</li>
                        <li id="<?php echo $generator_id; ?>_shortcode_load" onclick="cmshowcase_shortcode_load_menu('<?php echo $generator_id; ?>',this)">Load Shortcode</li>

                    </ul>

                    <div id="<?php echo $generator_id; ?>_cmshortcode" class="postbox">

                        <div id="<?php echo $generator_id; ?>_sctxt">
                            <div class="cm_shortcode_info"><?php echo __($shortcode_label,$this->showcase_id); ?></div>
                            <textarea class="cmshortcodetextarea" id="cmsctxt"></textarea>
                           
                            <div class="cmshowcase_buttons_area">
                                <span class="howto"><?php echo  __('You can use the full shortcode above directly on your page, but if you prefer you can save it, giving it an Alias instead, so you have a shorter version of the shortcode that you can load and edit in the future. The Alias name should be short and unique.',$this->showcase_id); ?></span>
                                <?php echo __('Save As:',$this->showcase_id); 

                                 $saved_alias = cmshowcase_get_saved_shortcodes($this->showcase_id,$generator_id);


                                ?>  

                                
                                    <select class="cmshowcase_select_shortcode_name" id="cmshowcase_override_shortcode_name" onchange="cmshowcase_override_option('<?php echo $generator_id; ?>')">

                                        <option value="null"><?php echo __("Create New",$this->showcase_id); ?> </option>

                                        <?php

                                        if($saved_alias) {

                                            foreach ($saved_alias as $name => $value) { ?>
                                        
                                             <option value="<?php echo $name; ?>"><?php echo $name; ?> </option>


                                        <?php

                                        }


                                        }

                                        

                                        ?>

                                    </select>

                               

                                <input type="text" id="new_shortcode" placeholder="<?php echo __('Give it a short name',$this->showcase_id); ?>"> 

                                <a class="button" id="save_shortcode_alias" onclick="cmshowcase_save_shortcode('<?php echo $generator_id; ?>')"><?php echo __('Save Shortcode Alias',$this->showcase_id); ?></a><span class="cmshowcase_message_area"></span>
                                


                                <div id="cmshowcase_saved_shortcodes"></div>

                            </div>    
                        </div>

                        <div id="<?php echo $generator_id; ?>_phptxt" style="display:none;">
                        <div class="cm_shortcode_info"><?php echo __($php_label,$this->showcase_id); ?></div>
                        <textarea class="cmshortcodetextarea" id="cmphptxt"></textarea>
                        <div class="cmshowcase_buttons_area">
                            </div> 
                        </div>

                         <div id="<?php echo $generator_id; ?>_loadtxt" style="display:none;">
                        <div class="cm_shortcode_info"><?php echo __($load_label,$this->showcase_id); ?></div>
                        <textarea class="cmshortcodetextarea" id="cmloadtxt"></textarea>
                        <div class="cmshowcase_buttons_area">
                            <a class="button button-primary" onclick="cmshowcase_load_shortcode('<?php echo $generator_id; ?>')">Load Shortcode</a>
                        </div>    
                        </div>
                        
                    </div>

                    <h2><?php echo __($preview_title_label,$this->showcase_id); ?></h2>
                    <?php

                        if($preview_description_label!='') {

                      ?>

                      <div class="cm_preview_description"><?php echo __($preview_description_label,$this->showcase_id); ?></div>
                      
                      <?php  
                            }
                      ?>

                     
                     <ul id="cm_preview_bg_toggle">
                        <li id='<?php echo $generator_id; ?>_preview_l' class='cm_preview_toggle_current' onclick="cmshowcase_shortcode_preview_l('<?php echo $generator_id; ?>',this)"><?php echo $preview_light_bg_label; ?></li>
                        <li id='<?php echo $generator_id; ?>_preview_d' onclick="cmshowcase_shortcode_preview_d('<?php echo $generator_id; ?>',this)"><?php echo $preview_dark_bg_label; ?></li>
                     </ul>
                    

                    <div id="<?php echo $generator_id; ?>_cmpreview" class='cmshowcase_light_cmpreview' style="display:block;"></div>



                </div>
            </div>
                <div class="cmshortcode_clear">&nbsp;</div>

                <script type="text/javascript">
                jQuery(document).ready(function($){
                cmshowcase_build_shortcode('<?php echo $generator_id; ?>');
                cmshowcase_view_shortcodes('<?php echo $generator_id; ?>');
                //to display current layout options
                var cur_layout = jQuery('#<?php echo $generator_id; ?> #layout').val();
                var e = document.getElementById('<?php echo $generator_id; ?>_'+cur_layout);
                if(e!=null) {
                    e.style.display = 'block';
                }
                
                var slayout_callbacks = [];

                <?php

                foreach ($this->layouts as $object) {

                    foreach ($object as $layout) {
                        $clb = isset($layout->shortcode_check) ? $layout->shortcode_check : '';
                        echo 'slayout_callbacks["'.$layout->layout_id.'"] = "'.$clb.'";';
                    }

                }

                ?>

               
                });
                </script>

            </div>
            <?php

            $display = 'none';

            }

            ?>
               

        </div>
        <div class="cmshortcode_clear">&nbsp;</div>


        <?php

        }

        function enqueue_generator_scripts() {

            //necessary default scripts
            wp_enqueue_script( 'jquery' );
            wp_enqueue_script( 'media-upload' );
            wp_enqueue_script( 'thickbox' );
            wp_enqueue_script( 'wp-color-picker' );
            wp_enqueue_style( 'wp-color-picker' );

            //admin css
            wp_deregister_style( 'cmshowcase-admin-style' );
            wp_register_style( 'cmshowcase-admin-style', plugins_url( '/css/admin.css', __FILE__) , array() , false, false);
            wp_enqueue_style( 'cmshowcase-admin-style' );

            //generator javascript
            wp_deregister_script( 'cmshowcase-generator' );
            wp_register_script( 'cmshowcase-generator', plugins_url( '/js/shortcode_generator.js', __FILE__) , array('jquery') , false, false);
            wp_enqueue_script( 'cmshowcase-generator' );

            //for the preview to work
            wp_localize_script( 'cmshowcase-generator', 'ajax_object', array(
                'ajax_url' => admin_url( 'admin-ajax.php' )
            ));

            

        }

        
       

        function add_new_shortcode($values) {

            add_filter( 'widget_text', 'do_shortcode' );
            add_filter( 'the_excerpt', 'do_shortcode' );

            foreach ($values as $shortcode => $value) {
                if(isset($value['callback'])) {
                  add_shortcode( $shortcode , $value['callback'] );
                  // add_shortcode( $shortcode , array(  $this->showcase_object ,'shortcode_handler') );
                }
            }
        }


        function add_layouts($layouts){

            foreach ($layouts as $layoutk => $layoutv) {

                require_once (dirname(__FILE__).'/../layouts/'.$layoutk.'/layout.php');
                
                $constructor = $layoutv['class'];
                $this->layouts[$this->showcase_id][$layoutk] = new $constructor($this->showcase_id);
                unset($constructor);
            } 

        }

    }
}

?>