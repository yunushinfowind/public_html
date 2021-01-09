<?php
// VISUAL COMPOSER CLASS

class cmshowcase_VCExtendAddonClass {

    private $showcase_id;
    private $title;
    private $description;
    private $shortcode;

    function __construct($id,$title,$description,$shortcode) {

        $this->showcase_id = $id;  
        $this->title = $title;
        $this->description = $description;
        $this->shortcode = $shortcode;
      

        // We safely integrate with VC with this hook
        add_action( 'init', array( $this, 'integrateWithVC' ) );

    }
 
    public function integrateWithVC() {
      // Check if Visual Composer is installed
       if ( !defined('WPB_VC_VERSION') || !function_exists('vc_map')) {
          // Display notice that Visual Compser is required
          // add_action('admin_notices', array( $this, 'showVcVersionNotice' ));
          return;
      }

      $manage_url = get_admin_url().'edit.php?post_type='.$this->showcase_id.'&page='.$this->showcase_id.'_shortcode_generator';
      $description = __("Choose one of the previously saved shortcode Alias. <br> <a href='".$manage_url."' target='_blank'>Click here to go to your shortcode generator page</a>", $this->showcase_id);
 
      $saved_shortcodes = get_option($this->showcase_id.'_saved_shortcodes',array());

      $options = array();
      
      $options[__('Please select...',$this->showcase_id)] = 'null';

      $i = 0;

      if(count($saved_shortcodes)>0) {

        foreach ($saved_shortcodes as $shortcode) {
        
          foreach ($shortcode as $key => $value) {
            $options[$key] = $key;
            $i++;
          }
        
        }

      } 

    if($i == 0) {

        $description = __("Looks like you don't have any saved shortcode Alias. <br> <a href='".$manage_url."' target='_blank'>Click here to go to your shortcode generator page</a>.", $this->showcase_id);
    }

    if(function_exists('vc_map')) {
      vc_map( array(
          "name" => __($this->title, $this->showcase_id),
          "description" => __($this->description, $this->showcase_id),
          "base" => $this->shortcode,
          "class" => "",
          //"front_enqueue_css" => plugins_url('resources/global.css', dirname(__FILE__)),
          "front_enqueue_js" => plugins_url('js/visual_composer.js', __FILE__),
          "icon" => plugins_url('img/icon32.png', dirname(__FILE__)),
          "category" => __('Content', 'ttshowcase'),
          "params" => array(
              array(
                "admin_label" => true,
                "type" => "dropdown",
                "holder" => "hidden",
                "class" => "",
                "heading" => __("Saved shortcode to display", $this->showcase_id),
                "param_name" => "alias",
                "value" => $options,
                "description" => $description
            )
          ),
          "custom_markup" => "",
      ));
    }

  //close integrateWithVC
  }

//close class
}


?>