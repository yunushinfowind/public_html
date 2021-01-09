<?php

/*
Last Modified: December 1st 2013
Author: Carlos Moreira
*/

//custom post type creator class
require_once dirname( __FILE__ ) . '/class-cpt.php';
//settings page creator class
require_once dirname( __FILE__ ) . '/class-settings.php';




if ( !class_exists('cmshowcase' ) ) {

	class cmshowcase {

		public $cmshowcase_id;			//string
		public $cmshowcase_options;		//array
		public $layout_objects; 		//array 
		public $cmswhocase_settings;	//array

		function __construct( $id,$options = array() ) {

			$this->cmshowcase_id = $id;
			$this->cmshowcase_options = $options;
			$this->layouts = array();


			//set support for thumbnails for this custom post type
			add_action( 'init', array($this,'thumbnail_support'));

			
			//First thing we do, if options/settings exist, we 
			//check if any setting should be used to construct the Custom Post Type
			if (array_key_exists('options', $this->cmshowcase_options)) {
				$this->cmshowcase_options = $this->build_options($this->cmshowcase_options);
			}


			//Get the Names
			$names = array();
			if (array_key_exists('names', $this->cmshowcase_options)) {
				$names = $this->cmshowcase_options['names'];
			} else {
				//set default names if array doesn't exist
				$names['singular'] = $id;
				$names['plural'] = $id;
				$names['slug'] = strtolower( str_replace( ' ', '_', $id ) );
			}

			//Gets the arguments to be used when building the custom post type
			$args = array();
			if (array_key_exists('args', $this->cmshowcase_options)) {
				$args = $this->cmshowcase_options['args'];
			}

			//We now have all the necessary parameters and we can 
			//build the Custom Post Type
			$cpt = new cmshowcase_custom_post_type($id,$args,$names);


			//Now we check if there are custom fields to be created
			if (array_key_exists('meta_boxes', $this->cmshowcase_options)) {
				foreach ($this->cmshowcase_options['meta_boxes'] as $fieldkey => $fieldvalue) {

					$cpt_id = $this->cmshowcase_id;
					$metabox_id = $fieldkey;
					$title = (isset($fieldvalue['title'])) ? $fieldvalue['title'] : $fieldkey;
					$description = (isset($fieldvalue['description'])) ? $fieldvalue['description'] : '';
					$fields = (isset($fieldvalue['fields'])) ? $fieldvalue['fields'] : array();
					$context = (isset($fieldvalue['context'])) ? $fieldvalue['context'] : 'normal';
					$priority = (isset($fieldvalue['priority'])) ? $fieldvalue['priority'] : 'high';

					//if it's a preset meta box

					if(isset($fieldvalue['preset'])) {
		
						$cpt->add_preset_meta_box($cpt_id, $fieldvalue['preset'], $title, $context, $priority);
					}

					//build custom meta box
					else {
					$cpt->add_meta_box($metabox_id,$title,$description,$fields,$context,$priority);
					}
				}
			}

			//add taxonomies
			if (array_key_exists('taxonomies', $this->cmshowcase_options)) {
				foreach ($this->cmshowcase_options['taxonomies'] as $taxkey => $taxvalue) {

					$taxid = $id.'_'.strtolower( str_replace( ' ', '_', $taxkey ) );

					//Get the Names
					$names = array();
					if ($taxvalue['names']) {
						$names = $taxvalue['names'];
					} else {
						//set default names if array doesn't exist
						$names['singular'] = ucwords($taxkey);
						$names['plural'] = ucwords($taxkey);
						$names['slug'] = $taxid;
					}

					$args = array();
					if(isset($taxvalue['args'])) {
						$args = $taxvalue['args'];
					}

					$labels = array();
					if(isset($taxvalue['labels'])) {
						$labels = $taxvalue['labels'];
					}

					$fields = array();
					if(isset($taxvalue['fields'])) {
						$fields = $taxvalue['fields'];
					}

					//Build the Taxonomies
					$cpt->add_taxonomy( $taxid, $names, $args, $labels, $fields );
				}

				//We set the final options array to the global array
				global $cmshowcase;
				$cmshowcase[$id] = $this->cmshowcase_options;


			}

			//add extra addon features
			if (array_key_exists('addons', $this->cmshowcase_options)) {
				//addons class
				require_once dirname( __FILE__ ) . '/class-addons.php';
				$addons = new cmshowcase_addons($id,$this->cmshowcase_options['addons'],$this->cmshowcase_options);

			}


			// Build Options/Settings Page

			if (array_key_exists('options', $this->cmshowcase_options)) {

				$this->add_settings_page($this->cmshowcase_options['options']);

			}

			
    	
    	}

    	public function add_settings_page($options){
			//add options
			if (is_array($options)) {

				$id = $this->cmshowcase_id;
				
				foreach ($options as $optkey => &$opt) {	

					$title = isset($opt['menu_title']) ? $opt['menu_title'] : $optkey;
					$menu_title = isset($opt['menu_title']) ? $opt['menu_title'] : $optkey;
					$description = isset($opt['description']) ? $opt['description'] : '';
					$capability = isset($opt['capability']) ? $opt['capability'] : 'manage_options';
					$sections = array();

					//we reorder the sections
					if(isset($opt['sections'])){
						$opt['sections'] = $this->order_sections($opt['sections']);
					}
					//we prepare the section array so they have a unique identifier (section_id)


					if(isset($opt['sections'])){
						foreach ($opt['sections'] as $key => &$value) {
							if(isset($value['section_id'])) {
								$value['section_id'] = $id.'_'.$value['section_id'];
							} else {
								$value['section_id'] = $id.'_'.$key;
							}
						}

					$sections = isset($opt['sections']) ? $opt['sections'] : array();
					}

					
					$settings = new cmshowcase_settings($id,$title,$menu_title,$capability,$description,$sections);
			        
				}

			}    
    	}


    	function thumbnail_support() {


				global $_wp_theme_features;
				if (isset($_wp_theme_features['post-thumbnails']) && $_wp_theme_features['post-thumbnails'] == 1) {
					return;
				}

				if (isset($_wp_theme_features['post-thumbnails'][0]) && is_array($_wp_theme_features['post-thumbnails'][0]) && count($_wp_theme_features['post-thumbnails'][0]) >= 1) {
					array_push($_wp_theme_features['post-thumbnails'][0], $this->cmshowcase_id );
					return;
				}

				if (empty($_wp_theme_features['post-thumbnails'])) {
					$_wp_theme_features['post-thumbnails'] = array(
						array(
							$this->cmshowcase_id
						)
					);
					return;
				}

    	}

    	function order_sections($sections) {


	        $sorter=array();
	        $ret=array();
	        reset($sections);

	        foreach ($sections as $ii => $va) {
	            $sorter[$ii]=$va['section_order'];
	        }
	        asort($sorter);
	        foreach ($sorter as $ii => $va) {
	            $ret[$ii]=$sections[$ii];
	        }

	        $sections = $ret;

	        return $sections;

    	}


    	function build_options($options) {

    		$return = $options;

    		// go throw all sub arrays to reach the fields array

    		foreach ($options['options'] as $settings) {

    			if(isset($settings['sections'])){

    				foreach ($settings['sections'] as $section_id => $section) {

    					if(isset($section['fields'])){

    						$section_cpt_id = $this->cmshowcase_id.'_'.$section_id;

		    				foreach ($section['fields'] as $id => $field) {

		    					//once we reach the fields array, if there is a key 'use_as'
		    					//we change the array values with the options set
		    					if(isset($field['use_as'])) {

		    						$option = $id;
		    						$default = (isset($field['default']) ? $field['default'] : '');

		    						switch ($field['use_as']) {

									    case 'singular':

									    	$return['names']['singular'] = cmshowcase_get_option( $option, $section_cpt_id, $default);
									        break;

									    case 'plural':
									    	
									    	$return['names']['plural'] = cmshowcase_get_option( $option, $section_cpt_id, $default);
									        break;

									    case 'slug':

									    	$return['names']['slug'] = cmshowcase_get_option( $option, $section_cpt_id, $default);
									    	$return['args']['rewrite'] = array('slug' => cmshowcase_get_option( $option, $section_cpt_id, $default));
									        break;

									    case 'icon':
									    	//in case the field is empty we default to the value already set, if it exists
									    	$default = (isset($return['args']['menu_icon']) ? $return['args']['menu_icon'] : $default);
									    	$value = cmshowcase_get_option( $option, $section_cpt_id, $default);
									    	$value = $value != '' ? $value : $default;
									    	$return['args']['menu_icon'] = $value;
									        break;

									    case 'taxonomy_plural':
									    	$value = cmshowcase_get_option( $option, $section_cpt_id, $default);
									    	if(isset($return['taxonomies'][$field['use_as_target']])) {
									    		$return['taxonomies'][$field['use_as_target']]['names']['plural'] = $value;
									    	}
									    	break;

									     case 'taxonomy_singular':
									    	$value = cmshowcase_get_option( $option, $section_cpt_id, $default);
									    	if(isset($return['taxonomies'][$field['use_as_target']])) {
									    		$return['taxonomies'][$field['use_as_target']]['names']['singular'] = $value;
									    	}
									    	break;

									    case 'thumb_size_width':
									    	$value = cmshowcase_get_option ($option, $section_cpt_id, $default);
									    	if(isset($return['addons']['thumb-sizes'][$field['use_as_target']])) {
									    		$return['addons']['thumb-sizes'][$field['use_as_target']]['width'] = $value;
									    	}
									    	break;

									    case 'thumb_size_height':
									    	$value = cmshowcase_get_option ($option, $section_cpt_id, $default);
									    	if(isset($return['addons']['thumb-sizes'][$field['use_as_target']])) {
									    		$return['addons']['thumb-sizes'][$field['use_as_target']]['height'] = $value;
									    	}
									    	break;

									     case 'thumb_size_crop':
									    	$value = cmshowcase_get_option ($option, $section_cpt_id, $default);
									    	if(isset($return['addons']['thumb-sizes'][$field['use_as_target']])) {

									    		$bolean = true;
									    		if($value == false || $value == "false") {
									    			$bolean = false;
									    		}

									    		$return['addons']['thumb-sizes'][$field['use_as_target']]['crop'] = $bolean;
									    	}
									    	break;

									     case 'exclude_from_search':

									     	$value = cmshowcase_get_option ($option, $section_cpt_id, $default);
									     	if($value=='on') {
									     		$bolean = true;
									     	}
									     	else {
									     		$bolean = false;
									     	}

									     	$return['args']['exclude_from_search'] = $bolean;

									     	break;

									     //IN DEVELOPMENT  

									    case 'labels':
									    	break;

									    case 'args':
									    	break;

									    case 'cpt_supports':
									    	break;

									    case 'meta_boxes':
									    	break;

									    case 'taxonomies':
									    	break;

									}

		    					}
		    				
		    				}

		    			}
    				}

    			}
    		}

    		return $return;
    	}    	

	}

}

?>