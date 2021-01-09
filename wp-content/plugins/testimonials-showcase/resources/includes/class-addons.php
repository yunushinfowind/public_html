<?php

/*

Version 0.1
Last Modified: November 12 2013
Author: Carlos Moreira

*/

if ( !class_exists( 'cmshowcase_addons' ) ) {
	class cmshowcase_addons {

	    /*
	    We start by setting some variables that we will use in several functions
	    */
	    private $showcase_id;
	    private $showcase_options;
	    private $columns_values;
	    public $admin_entries_num;
	    public $editor_boxes;
	    public $showcase_taxonomies;


	    /*
	    Constructor class that gets all the necessary values to build the settings pages
	    */

	    function __construct($id,$addons,$options) {

	    	$this->showcase_id = $id;
	    	$this->showcase_options = $options;

	    	foreach ($addons as $key => $value) {

	    		
	    		switch ($key) {
	    			case 'thumb-sizes':
	    				$this->build_custom_thumb_size($value);
	    				break;

	    			case 'admin-archive-columns':

	    				$this->build_admin_archive_colums($value);
	    				break;
	    			case 'move-editor-below':
	    				$this->move_editor_below($value);
	    				break;

	    			case 'single-page-filters':
	    				$this->single_page_filters($value);
	    				break;

	    			case 'single-template-filters':
	    				$this->single_template_filters($value);
	    				break;

	    			case 'vector-icon':
	    				$this->vector_icon_build($value);
	    				break;
	    			
	    			case 'font-icon':
	    				$this->font_icon_build($value);
	    				break;

	    			case 'admin-entries':
	    				$this->admin_entries($value);
	    				break;
	    			case 'admin-archive-taxonomy-filter':
	    				$this->admin_tax_filter($value);
	    				break; 

	    			default:
	    				# code...
	    				break;
	    		}


	    	}
	    }

	    function admin_tax_filter($value) {

	    	$this->showcase_taxonomies = $value['taxonomies'];

	    	add_action( 'restrict_manage_posts', array($this,'taxonomy_filters') );

	    }

	    function taxonomy_filters(){

			global $typenow;
		 
			// an array of all the taxonomyies you want to display. Use the taxonomy name or slug
			$taxonomies = array('ttshowcase_groups');
		 
			// must set this to the post type you want the filter(s) displayed on
			if( $typenow == $this->showcase_id ){
		 
				foreach ($taxonomies as $tax_slug) {
					$tax_obj = get_taxonomy($tax_slug);
					$tax_name = $tax_obj->labels->all_items;
					$terms = get_terms($tax_slug);
					if(count($terms) > 0) {
						echo "<select name='$tax_slug' id='$tax_slug' class='postform'>";
						echo "<option value=''>$tax_name</option>";
						foreach ($terms as $term) { 
							$current_tax_slug = isset( $_GET[$tax_slug] ) ? $_GET[$tax_slug] : false;
							echo '<option value='. $term->slug, $current_tax_slug == $term->slug ? ' selected="selected"' : '','>' . $term->name .' (' . $term->count .')</option>'; 
						}
						echo "</select>";
					}
				}
			}

	    }

	    function single_page_filters($array) {

	    	foreach ($array as $key) {
	    		add_filter( 'the_content', $key );
	    	}

	    }

	    function single_template_filters($array) {

	    	foreach ($array as $key) {
	    		add_filter( 'single_template', $key );
	    	}

	    }
		
		//small fix to move the custom boxes above the editor
	    function move_editor_below($array) {

				$this->editor_boxes = $array;

				add_action('admin_footer',array($this,'admin_footer_trigger'));

	    }


	   	function admin_entries($value) {

	   		$this->admin_entries_num = $value;
	   		add_filter('pre_get_posts', array(&$this,'cmshowcase_posts_per_page_admin'));

	   	}

	   	public function cmshowcase_posts_per_page_admin($wp_query) {

		  if (is_post_type_archive( $this->showcase_id ) && is_admin() ) {    	

				  $wp_query->set( 'posts_per_page', $this->admin_entries_num  );
			
		  		
		  	}
		}


	    public function admin_footer_trigger() {

			global $post;
			if ( get_post_type($post) == $this->showcase_id) {
			?>
				<script type="text/javascript">

				<?php 
					foreach ($this->editor_boxes as $box) {
						echo "jQuery('#".$box."').insertBefore('#postdivrich');";
					}
				?>

				</script>
			<?php
			}

				

	    }

	    function build_custom_thumb_size($values) {

	    foreach ($values as $image => $value) {

	    	$crop = false;

			if ($value['crop'] == "true" || $value['crop'] == true  ) {
				$crop = true;
			}

			$id = $this->showcase_id.'_'.$value['id'];


			add_image_size( $id, 
				$value['width'], 
				$value['height'], 
				$crop);
			}

	    }

	    function build_admin_archive_colums($value) {

	    	$this->columns_values = $value;

			add_filter('manage_posts_columns', array(&$this,'columns_head'));
			add_action('manage_posts_custom_column', array(&$this,'columns_content'), 10, 2);

			add_filter( 'manage_edit-'.$this->showcase_id.'_sortable_columns', array(&$this,'ordering_columns') );  


	    }

	    //Add new column 
		function columns_head($defaults) {

			global $post;

		    if (isset($post->post_type) && $post->post_type == $this->showcase_id) {

		    	foreach ($this->columns_values as $key => $value) {
		    		$defaults[$key] = __($value['title'],$this->showcase_id);

		    	}

				
			}
			//$defaults = cmshowcase_translate_array($defaults,$this->showcase_id);
			return $defaults;
		}




		//set column content
		function columns_content($column_name, $post_ID) {
			
			global $post;

		    if ($post->post_type == $this->showcase_id) {

		    	if(isset($this->columns_values[$column_name])){
		    				
    				$value = $this->columns_values[$column_name];
    				

    				if($value['type']=='thumbnail'){
							
							if($value['source']=='featured_image') {

								echo get_the_post_thumbnail($post_ID, array(50,50));

							}			
					}

					if($value['type']=='taxonomy'){

							$term_list = wp_get_post_terms($post_ID, $value['source'], array("fields" => "names"));
						      foreach ( $term_list as $term ) {
						        echo $term.'<br>';
						        }

					}
					
					if($value['type']=='text'){
						if(is_array($value['source'])) {

							$field_id_name 	= '_'.$value['source'][0].'_'.$value['source'][1];
							$meta = get_post_custom( $post_ID );

							if(isset($meta[$field_id_name])){

								if(isset($value['limit'])) {
									echo substr($meta[$field_id_name][0], 0, $value['limit']).' (...)';
								} 
								else {
									echo $meta[$field_id_name][0];
								}

								
							}

						}

					}	

					if($value['type']=='order'){

						
						
						if($value['source']=='menu_order') {

								echo $post->menu_order;

						}	

					}	
					
		    	}

			}
		}


		public function ordering_columns($columns) {
		
			  

			   	 $columns['menu_order'] = 'menu_order';
			   
			  
			 
			  return $columns;

		}

		function font_icon_build($font) {

			

			$wp_version =  floatval( get_bloginfo( 'version' ) );
			if($wp_version >= 3.8) {
				$this->vector_font_icon = $font;
				add_action('admin_head', array(&$this,'font_icon'));
			} 

			

		}

		function font_icon() {
			$icon = $this->vector_font_icon;
			$cpt = $this->showcase_id;
			echo '

			<style> 
			#adminmenu #menu-posts-'.$cpt.' div.wp-menu-image:before { content: "'.$icon.'"; }
			</style>

			';

		}


		function vector_icon_build($icon) {

			$wp_version =  floatval( get_bloginfo( 'version' ) );
			if($wp_version <= 3.8) {

				$this->vector_icon = $icon;
				add_action( 'admin_head', array(&$this,'vector_icon_css') );

			}


		}

		function vector_icon_css() { 

			$icon = $this->vector_icon;
			$cpt = $this->showcase_id;

			?>

		<style>

			#icon-edit.icon32-posts-<?php echo $cpt; ?> {

				background: url('<?php echo plugins_url($icon,dirname(__FILE__)); ?>') no-repeat 6px 6px;
				background-size: 24px 24px;

			}

			#menu-posts-<?php echo $cpt; ?> .wp-menu-image {

				background: url('<?php echo plugins_url($icon,dirname(__FILE__)); ?>') no-repeat; 
				background-size: 16px 16px;
				background-position: 6px 6px !important;
				

			}

			#menu-posts-<?php echo $cpt; ?> .wp-menu-image img {
				opacity: 0.5;
				width:16px;

			}



		</style>
		<?php
		}


	}

}

?>