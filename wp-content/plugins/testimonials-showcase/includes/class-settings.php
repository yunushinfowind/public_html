<?php
/*

Version 0.1
Last Modified: November 11 2013
Author: Carlos Moreira
Inspired by work of: Tareq Hasan (view below)

To prepare the settings, we build a new class.
Then we use Tarik's API class for now to do the rest.

*/

if ( !class_exists( 'cmshowcase_settings' ) ) {
class cmshowcase_settings {

    /*
    We start by setting some variables that we will use in several functions
    */
    public $showcase_id;
    public $showcase_sections;
    public $settings_page_title;
    public $menu_title;
    public $capability;

    /*
    Constructor class that gets all the necessary values to build the settings pages
    */

    function __construct($id,$title,$menu_title,$capability,$description,$sections) {

        //we star by setting the global variables
        $this->showcase_id = $id;
        $this->showcase_sections = $sections;
        $this->settings_page_title = $title;
        $this->menu_title = $menu_title;
        $this->capability = $capability;
        
        //We add the new menu entry
        add_action( 'admin_menu', array($this,'add_setings_page'));

        //Add the init hook to register the settings sections and fields 
        add_action( 'admin_init', array($this, 'admin_init') );

        //hook to call necessary scripts for the page to work properly
        add_action( 'admin_enqueue_scripts', array( $this, 'admin_enqueue_scripts' ) );

        
    }

    public function add_setings_page() {

            $id = $this->showcase_id;
            $title = $this->settings_page_title;
            $menu_title = $this->menu_title;
            $capability = $this->capability; 

            $parent_slug = 'edit.php?post_type='.$id;
            $page_title = __($title,$this->showcase_id);
            $menu_title = __($menu_title,$this->showcase_id);
            $capability = $capability;
            $slug = strtolower( str_replace( ' ', '_', $title ) );
            $menu_slug = $id.'_'.$slug;
            $function = array($this, 'plugin_page');
            
           add_submenu_page( $parent_slug, $page_title, $menu_title, $capability, $menu_slug, $function );

    }

    /**
     * Enqueue scripts and styles
     */
    function admin_enqueue_scripts() {
        wp_enqueue_script( 'jquery' );
        //wp_enqueue_script( 'media-upload' );
        wp_enqueue_script( 'thickbox' );
        wp_enqueue_script( 'wp-color-picker' );
        wp_enqueue_style( 'wp-color-picker' );
    }

    /**
     * Init function where the sections and fields are registred
     * This needs to be called from a admin_init hook
     */
    function admin_init() {

        $sections = $this->showcase_sections;
    
        foreach ( $sections as $section ) {

            if($section){

                if(isset($section['section_id'])) {
                    //check if it already exists if not add option
                    if ( false == get_option( $section['section_id'] ) ) {
                        add_option( $section['section_id'] );
                    }

                    if ( isset($section['section_description']) && !empty($section['section_description']) ) {

                        //first we translate the description
                        $description = __($section['section_description'],$this->showcase_id);
                        
                        $description = '<div class="inside">'.$description.'</div>';
                        $callback = create_function('', 'echo "'.str_replace('"', '\"', $description).'";');
                    } else {
                        $callback = '__return_false';
                    }

                    //We translate the title
                    $title = isset($section['section_title']) ? __($section['section_title'],$this->showcase_id) : $section['section_id'];

                    add_settings_section( $section['section_id'], $title, $callback, $section['section_id'] );


                    //register settings fields
                    if(isset($section['fields'])) {

                        foreach ( $section['fields'] as $fieldkey => $fieldvalues ) {
                            
                            $type = isset( $fieldvalues['type'] ) ? $fieldvalues['type'] : 'text';
                            $default = isset( $fieldvalues['default'] ) ? $fieldvalues['default'] : '';

                            //translate fields that can be translated
                            $label = isset( $fieldvalues['label'] ) ? __($fieldvalues['label'],$this->showcase_id) : $fieldkey.'_';
                            $description = isset( $fieldvalues['description'] ) ? __($fieldvalues['description'],$this->showcase_id) : '';

                            $args = array(
                                'id' => $section['section_id'].'['.$fieldkey.']',
                                'type' => $fieldvalues['type'],
                                'description' => $description,
                                'name' => $section['section_id'].'['.$fieldkey.']',
                                'section' => $section['section_id'],
                                'size' => isset( $fieldvalues['size'] ) ? $fieldvalues['size'] : null,
                                'options' => isset( $fieldvalues['options'] ) ? cmshowcase_translate_array($fieldvalues['options'],$this->showcase_id) : '',
                                'default' => isset( $fieldvalues['default'] ) ? $fieldvalues['default'] : '',
                                'sanitize_callback' => isset( $fieldvalues['sanitize_callback'] ) ? $fieldvalues['sanitize_callback'] : '',
                                'value' =>  cmshowcase_get_option( $fieldkey, $section['section_id'], $default ) 
                            );

                            add_settings_field( $section['section_id'] . '[' . $fieldkey . ']', $label, 'cmshowcase_build_field_'.$fieldvalues['type'], $section['section_id'], $section['section_id'], $args );
                        
                        }

                    }
                    

                    register_setting( $section['section_id'], $section['section_id'], array( $this, 'sanitize_options' ) );
                }
            }

        }

    }



    function plugin_page() {

        echo '<div class="wrap">';

        echo '<div id="icon-edit" class="icon32 icon32-posts-'.$this->showcase_id.'"><br></div>';
        echo '<h2>' . __($this->settings_page_title,$this->showcase_id) . '</h2>';

        if(isset($_GET['settings-updated']) && $_GET['settings-updated'] == 'true') {

            $updated = __('Settings Updated',$this->showcase_id);

            echo '<div id="message" class="updated below-h2">
                    <p>'.$updated.'</p>
                 </div>';
        }

        $this->show_navigation();
        $this->show_forms();

        echo '</div>';
    }

    /**
     * Show navigations as tab
     *
     * Shows all the settings section labels as tab
     */
    function show_navigation() {
        $html = '<h2 class="nav-tab-wrapper">';

        foreach ( $this->showcase_sections as $tab ) {

            $section_title = __($tab['section_title'],$this->showcase_id);

            $html .= sprintf( '<a href="#%1$s" class="nav-tab" id="%1$s-tab">%2$s</a>', $tab['section_id'], $section_title );
        }

        $html .= '</h2>';

        echo $html;
    }

    /**
     * Show the section settings forms
     *
     * This function displays every sections in a different form
     */
    function show_forms() {
        ?>
        <div class="metabox-holder">
            <div style="padding-left:10px;">
                <?php foreach ( $this->showcase_sections as $form ) { ?>
                    <div id="<?php echo $form['section_id']; ?>" class="group">
                        <form method="post" action="options.php">

                            <?php do_action( 'wsa_form_top_' . $form['section_id'], $form ); ?>
                            <?php settings_fields( $form['section_id'] ); ?>
                            <?php do_settings_sections( $form['section_id'] ); ?>
                            <?php do_action( 'wsa_form_bottom_' . $form['section_id'], $form ); ?>

                            <div style="padding-left: 10px">
                                <?php submit_button(); ?>
                            </div>
                        </form>
                    </div>
                <?php } ?>
            </div>
        </div>
        <?php
        $this->script();
    }

    /**
     * Tabbable JavaScript codes
     *
     * This code uses localstorage for displaying active tabs
     */
    function script() {
        ?>
        <script>
            jQuery(document).ready(function($) {
                // Switches option sections
                $('.group').hide();
                var activetab = '';
                if (typeof(localStorage) != 'undefined' ) {
                    activetab = localStorage.getItem("activetab");
                }
                if (activetab != '' && $(activetab).length ) {
                    $(activetab).fadeIn();
                } else {
                    $('.group:first').fadeIn();
                }
                $('.group .collapsed').each(function(){
                    $(this).find('input:checked').parent().parent().parent().nextAll().each(
                    function(){
                        if ($(this).hasClass('last')) {
                            $(this).removeClass('hidden');
                            return false;
                        }
                        $(this).filter('.hidden').removeClass('hidden');
                    });
                });

                if (activetab != '' && $(activetab + '-tab').length ) {
                    $(activetab + '-tab').addClass('nav-tab-active');
                }
                else {
                    $('.nav-tab-wrapper a:first').addClass('nav-tab-active');
                }
                $('.nav-tab-wrapper a').click(function(evt) {
                    $('.nav-tab-wrapper a').removeClass('nav-tab-active');
                    $(this).addClass('nav-tab-active').blur();
                    var clicked_group = $(this).attr('href');
                    if (typeof(localStorage) != 'undefined' ) {
                        localStorage.setItem("activetab", $(this).attr('href'));
                    }
                    $('.group').hide();
                    $(clicked_group).fadeIn();
                    evt.preventDefault();
                });
            });
        </script>
        <?php
    }

    /*
    
    In Development

    */

    function sanitize_options( $options ) {

       return $options;

    }


    
    

}

}


?>