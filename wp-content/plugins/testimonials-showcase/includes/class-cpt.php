<?php

/*
Version 0.1
Last Modified: November 2 2013
Author: Carlos Moreira
*/

if ( !class_exists('cmshowcase_custom_post_type' ) ) {
class cmshowcase_custom_post_type

	{
		public $post_type_name;
		public $post_type_args;
		public $post_type_labels;
		public $taxonomy_id;
		public $tax_args;
		public $meta_box_args;

		//for custom meta boxes actions:
		public $featured_image_meta_box;

		
		
		/* Class constructor */
		public function __construct( $id, $args = array(), $names = array() )
		{
			// Set some global variables
			$this->post_type_name		= strtolower( str_replace( ' ', '_', $id ) );
			$this->post_type_args 		= $args;
			$this->post_type_names		= $names;
			$this->tax_args   			= array();
			$this->meta_box_args		= array();

			// Add action to register the post type, if the post type doesnt exist
			if( ! post_type_exists( $this->post_type_name ) )
			{
				add_action( 'init', array( &$this, 'register_post_type' ) );
			}

			// Save post hook
			$this->save();
		}
		
		/* Constructor method which registers the post type */
		public function register_post_type()
		{		
			
			$name = __($this->post_type_names['singular'],$this->post_type_name);
			$plural = __($this->post_type_names['plural'],$this->post_type_name);
			$slug = __( $this->post_type_names['slug'], $this->post_type_name );

			$passed_labels = array();
			if(isset($this->post_type_args['labels'])) { 
				
				// We go through the entries to make them translatable
				foreach ($this->post_type_args['labels'] as $key => $value) {
					
					$passed_labels[$key] = __($value,$this->post_type_name);
				}
				
				// In case there are wildcards, we run the function to replace wildcads with name
				$passed_labels = $this->build_label_names($this->post_type_names,$passed_labels);
			}
			
			//after building the labels, we set them again to the original array key
			$this->post_type_args['labels'] = $passed_labels;

			// default labels. 
			$default_labels = array(
					'name' 					=> _x( $plural, 'post type general name', $this->post_type_name ),
					'singular_name' 		=> _x( $name, 'post type singular name', $this->post_type_name ),
					'add_new' 				=> __( 'Add New', $this->post_type_name ).' '.strtolower( $name ),
					'add_new_item' 			=> __( 'Add New', $this->post_type_name ).' '.$name,
					'edit_item' 			=> __( 'Edit', $this->post_type_name ) .' '. $name,
					'new_item' 				=> __( 'New' , $this->post_type_name ).' '. $name,
					'all_items' 			=> __( 'All', $this->post_type_name ).' '.$plural,
					'view_item' 			=> __( 'View', $this->post_type_name ) . $name,
					'search_items' 			=> __( 'Search', $this->post_type_name ).' '. $plural,
					'not_found' 			=> __( 'No result found', $this->post_type_name ),
					'not_found_in_trash' 	=> __( 'No result found', $this->post_type_name ),
					'parent_item_colon' 	=> '',
					'menu_name' 			=> $plural,
					'slug'					=> $slug
				);


			
			// We set some default and overwite them with the given arguments.
			$args = array_merge(

				// Default
				array(
					'label' 				=> $plural,
					'labels' 				=> $default_labels,
					'public' 				=> true,
					'show_ui' 				=> true,
					'supports' 				=> array( 'title', 'editor' ),
					'show_in_nav_menus' 	=> true,
					'_builtin' 				=> false,
				),

				// Given args
				$this->post_type_args

			);

			// Register the post type
			register_post_type( $this->post_type_name, $args );
		}

		/* Function to replace wildcards in labels */
		function build_label_names($names,$labels) {
    		$final = array();
    		if (array_key_exists('singular', $names)) {
    			foreach ($labels as $key => $value) {
					$final[$key] = str_replace("%singular%", __($names['singular'],$this->post_type_name), $value);
    			}
    		}
    		if (array_key_exists('plural', $names)) {
    				foreach ($final as $key => $value) {
    					$final[$key] = str_replace("%plural%", __($names['plural'],$this->post_type_name), $value);
    				}
    			}
    		if (array_key_exists('slug', $names)) {
    				$final['slug'] = $names['slug'];
    		}
    		
    		return $final;
    	}
		
		/* Method to attach the taxonomy to the post type */
		public function add_taxonomy( $id, $names = array(), $args = array(), $labels = array(), $fields = array() )
		{
			if( ! empty( $id ) )
			{			
				// We need to know the post type name, so the new taxonomy can be attached to it.
				$post_type_name = $this->post_type_name;

				// Taxonomy properties
				$taxonomy_id		= $id;
				$taxonomy_names 	= $names;
				$taxonomy_labels	= $labels;
				$taxonomy_args		= $args;

				if( ! taxonomy_exists( $taxonomy_id ) )
					{
							//get the names and translate them if possible
							$name 		=  __($taxonomy_names['singular'],$this->post_type_name);
							$plural 	=  __($taxonomy_names['plural'],$this->post_type_name);


							//print_r($passed_labels);

							// Default labels, overwrite them with the given labels.
							$labels = array_merge(

								// Default
								array(
									'name' 					=> _x( $plural, 'Taxonomy general name',$this->post_type_name ),
									'singular_name' 		=> _x( $name, 'Taxonomy singular name',$this->post_type_name ),
								    'search_items' 			=> __( 'Search',$this->post_type_name ).' '. $plural,
								    'all_items' 			=> __( 'All',$this->post_type_name ).' '. $plural,
								    'parent_item' 			=> __( 'Parent',$this->post_type_name ) .' '. $name,
								    'parent_item_colon' 	=> __( 'Parent',$this->post_type_name ) .' '. $name . ';',
								    'edit_item' 			=> __( 'Edit',$this->post_type_name ) .' ' . $name, 
								    'update_item' 			=> __( 'Update',$this->post_type_name ) .' '. $name,
								    'add_new_item' 			=> __( 'Add New',$this->post_type_name ) .' '. $name,
								    'new_item_name' 		=> __( 'New',$this->post_type_name ),
								    'menu_name' 			=> __( $plural, $this->post_type_name ),
								),

								// Given labels
								$labels

							);

							// Default arguments, overwitten with the given arguments
							$args = array_merge(

								// Default
								array(
									'label'					=> $plural,
									'labels'				=> $labels,
									'public' 				=> true,
									'show_ui' 				=> true,
									'show_in_nav_menus' 	=> true,
									'_builtin' 				=> false,
									'hierarchical'			=> true
								),

								// Given
								$taxonomy_args

							);

							$this->tax_args[$taxonomy_id] = $args;
							
							// Add the taxonomy to the post type
							add_action( 'init', array ($this,'register_tax'));
					}
					else
					{
						add_action( 'init', array($this, 'register_tax_for_this'));
					}

					/*
	
					// IN CASE WE NEED TO ADD CUSTOM FiELDS FOR TAXONOMY
					// CURRENTLY WORKS ON PHP 5.3+

					//add custom fields if they exist
					if(!empty($fields)) {
						
						add_action( $taxonomy_id.'_add_form_fields', 

							function() use ($taxonomy_id,$fields)
							{
								
								$this->taxonomy_add_new_meta_field($taxonomy_id,$fields);
							}
						);

						add_action( $taxonomy_id.'_edit_form_fields',

							function() use ($taxonomy_id,$fields)
							{
								$this->taxonomy_edit_meta_field($taxonomy_id,$fields);
							}
						);


						add_action( 'edited_'.$taxonomy_id, array($this,'save_taxonomy_custom_meta'), 10, 2 );  
						add_action( 'create_'.$taxonomy_id, array($this,'save_taxonomy_custom_meta'), 10, 2 );
						
					}

					*/
					
			}
		}



		public function register_tax () {


			$post_type_name = $this->post_type_name;
			$tax_args = $this->tax_args;
			
			foreach ($tax_args as $tax_key => $args) {	
				// We go through the entries to make them translatable
				foreach ($args['labels'] as $key => &$value) {
					
					$args['labels'][$key] = __($value,$this->post_type_name);
					
				}	
				register_taxonomy( $tax_key, $post_type_name, $args );
			}
								

		}

		public function register_tax_for_this() {

				$taxonomy_id = $this->taxonomy_id;
				$post_type_name = $this->post_type_name;

				register_taxonomy_for_object_type( $taxonomy_id, $post_type_name );
				
		}




		//New Code for Taxonomy Fields
		//NEEDS TO BE IMPROVED TO CHECK FOR FIELD TYPES

		// Add term page
		public function taxonomy_add_new_meta_field($taxonomy,$fields) {
		
		// this will add the custom meta field to the add new term page


			foreach( $fields as $field => $args )
			{
			
				$label = isset( $args['label'] ) ? __($args['label'],$this->post_type_name) : $field;

			?>
			<div class="form-field">
				<label for="term_meta[<?php echo $field; ?>]"><?php echo $label; ?></label>

				<?php
						$description = isset( $args['description'] ) ? __($args['description'],$this->post_type_name) : '';
						
						$argsfinal = array();
						$argsfinal['name'] = 'term_meta['.$field.']';
						$argsfinal['id'] = 'term_meta['.$field.']';
						$argsfinal['type'] = isset( $args['type'] ) ? $args['type'] : 'text';
						$argsfinal['default'] = isset( $args['default'] ) ? $args['default'] : '';
						$argsfinal['value'] = esc_attr( isset($term_meta[$field]) ) ? esc_attr( $term_meta[$field] ) : '';
						$argsfinal['description'] = $description;
						$argsfinal['options'] = isset( $args['options'] ) ? $args['options'] : null;
						$argsfinal['size'] = isset( $args['size'] ) ? $args['size'] : null;

						call_user_func('cmshowcase_build_field_'.$argsfinal['type'], $argsfinal);	
						?>

			</div>
			
			<?php
			
			}
		}
		

		// Edit term page
		public function taxonomy_edit_meta_field($term,$fields) {
				//get current taxonomy id

				$t_id = intval($_GET['tag_ID']);
				// retrieve the existing value(s) for this meta field. This returns an array
				$term_meta = get_option( "taxonomy_$t_id" ); 
				
			
			foreach( $fields as $field => $args )
			{
				$label = isset( $args['label'] ) ? __($args['label'],$this->post_type_name) : $field;

				?>
				<tr class="form-field">
				<th scope="row" valign="top"><label for="term_meta[<?php echo $field; ?>]"><?php echo $label; ?></label></th>
					<td>
						<?php

						//we translate the description
						$description = isset( $args['description'] ) ? __($args['description'],$this->post_type_name) : '';

						$argsfinal = array();
						$argsfinal['name'] = 'term_meta['.$field.']';
						$argsfinal['id'] = 'term_meta['.$field.']';
						$argsfinal['type'] = isset( $args['type'] ) ? $args['type'] : 'text';
						$argsfinal['default'] = isset( $args['default'] ) ? $args['default'] : '';
						$argsfinal['value'] = esc_attr( isset($term_meta[$field]) ) ? esc_attr( $term_meta[$field] ) : '';
						$argsfinal['description'] = $description;
						$argsfinal['options'] = isset( $args['options'] ) ? $args['options'] : null;
						$argsfinal['size'] = isset( $args['size'] ) ? $args['size'] : null;

						call_user_func('cmshowcase_build_field_'.$argsfinal['type'], $argsfinal);	
						?>
					</td>
				</tr>
		<?php
			}
		}
		

		// Save extra taxonomy fields callback function.
		public function save_taxonomy_custom_meta( $term_id ) {
			if ( isset( $_POST['term_meta'] ) ) {
				$t_id = $term_id;
				$term_meta = get_option( "taxonomy_$t_id" );
				$cat_keys = array_keys( $_POST['term_meta'] );
				foreach ( $cat_keys as $key ) {
					if ( isset ( $_POST['term_meta'][$key] ) ) {
						$term_meta[$key] = $_POST['term_meta'][$key];
					}
				}
				// Save the option array.
				update_option( "taxonomy_$t_id", $term_meta );
			}
		}  

		//End Custom New Code
		
		public function add_preset_meta_box ($cpt_id, $preset, $title, $context = 'normal', $priority = 'high') {

			if($preset=='featured_image') {

				$this->featured_image_meta_box = array();
				$this->featured_image_meta_box['title'] = $title;
				$this->featured_image_meta_box['context'] = $context;
				$this->featured_image_meta_box['priority'] = $priority;

				add_action( 'do_meta_boxes', array($this, 'preset_meta_box_featured_image') );
			}
		}

		public function preset_meta_box_featured_image () {

			$cpt_id = $this->post_type_name;
			$title = $this->featured_image_meta_box['title'];
			$context = $this->featured_image_meta_box['context'];
			$priority = $this->featured_image_meta_box['priority'];

			remove_meta_box( 'postimagediv', $cpt_id, 'side' );
			add_meta_box( 'postimagediv', __($title,$this->post_type_name) , 'post_thumbnail_meta_box', $cpt_id, $context, $priority );

		}


		
		/* Attaches meta boxes to the post type */
		public function add_meta_box( $meta_id, $title, $description, $fields = array(), $context = 'normal', $priority = 'high' )
		{
			if( ! empty( $meta_id ) )
			{		
				// We need to know the Post Type name again
				$post_type_name = $this->post_type_name;

				// Meta variables	
				$box_id 		= $meta_id;//strtolower( str_replace( ' ', '_', $title ) );
				$box_title		= ucwords( str_replace( '_', ' ', $title ) );
				$box_description= $description;
				$box_context	= $context;
				$box_priority	= $priority;

				// Make the fields global
				global $custom_fields;

				$custom_fields[$box_id] = $fields;

				$this->meta_box_args[$box_id]['title'] = $box_title;
				$this->meta_box_args[$box_id]['description'] = $box_description;
				$this->meta_box_args[$box_id]['context'] = $box_context;
				$this->meta_box_args[$box_id]['priority'] = $box_priority;
				$this->meta_box_args[$box_id]['fields'] = $fields;

				//$box_id, $box_title, $box_description, $post_type_name, $box_context, $box_priority, $fields

				add_action( 'admin_init', array($this,'add_meta_boxes_execute'));
			}

		}

		public function add_meta_boxes_execute() {

			foreach ($this->meta_box_args as $box_id => $args) {
				
			
				//$box_id, $box_title, $box_description, $post_type_name, $box_context, $box_priority, $fields
				$box_title = $args['title'];
				$box_description = $args['description'];
				$post_type_name = $this->post_type_name;
				$box_context = $args['context'];
				$box_priority = $args['priority'];
				$fields = $args['fields'];
		
				//translate values
				$box_title = __($box_title,$this->post_type_name);

				add_meta_box(
					$box_id,
					$box_title, array ($this,'meta_boxes_process'),
					$post_type_name,
					$box_context,
					$box_priority,
					array( 'fields' => $fields, 'description' => $box_description )
				);
				
			}	



		}

		public function meta_boxes_process($post, $data) {


				global $post;

				// Nonce field for some validation
				wp_nonce_field( plugin_basename( __FILE__ ), 'custom_post_type' );

				// Get all inputs from $data
				$custom_fields = $data['args']['fields'];

				// Get Description and translate it
				$description = __($data['args']['description'],$this->post_type_name);

				// Get the saved values
				$meta = get_post_custom( $post->ID );

				// Check the array and loop through it
				if( ! empty( $description ) )
				{
					

					echo '<table class="form-table"><tbody>';

					if($description!='') {
						echo '<tr><td colspan="2">'.$description.'</td></tr>';
					}

					/* Loop through $custom_fields */

					foreach( $custom_fields as $field => $args )
					{

						$field_id_name 	= '_'.strtolower( str_replace( ' ', '_', $data['id'] ) ) . '_' . strtolower( str_replace( ' ', '_', $field ) );
						
						//get the field and translate it	
						$field_label = (isset($args['label']) ? __($args['label'],$this->post_type_name) : $field);
						$description = isset( $args['description'] ) ? __($args['description'],$this->post_type_name) : '';

						echo '<tr valign="top"><th scope="row">';
						echo '<label for="' . $field_id_name . '">' . $field_label . ': </label></th><td>';
						
						$argsfinal = array();
						$argsfinal['name'] = 'custom_meta['.$field_id_name.']';
						$argsfinal['id'] = 'custom_meta['.$field_id_name.']';
						$argsfinal['type'] = $args['type'];
						$argsfinal['default'] = isset( $args['default'] ) ? $args['default'] : '';
						$argsfinal['value'] = maybe_unserialize((isset($meta[$field_id_name][0]) ? $meta[$field_id_name][0] : ""));
						$argsfinal['description'] = $description;
						$argsfinal['options'] = isset( $args['options'] ) ? $args['options'] : null;
						$argsfinal['size'] = isset( $args['size'] ) ? $args['size'] : null;

						call_user_func('cmshowcase_build_field_'.$argsfinal['type'], $argsfinal);	
						
						echo '</td></tr>';

						
					}

					echo "</tbody></table>";
				}

					

		}


		
		
		/* 
		Listens for when the post type being saved 
		Needs to be improved for different types of fields
		*/
		public function save()
		{

			add_action( 'save_post', array($this,'save_post_process'));
		}


		public function save_post_process() {

			// Need the post type name again
			$post_type_name = $this->post_type_name;

			// Deny the wordpress autosave function
			if( defined('DOING_AUTOSAVE') && DOING_AUTOSAVE ) return;

			if(isset($_POST['custom_post_type'])){
			if ( ! wp_verify_nonce( $_POST['custom_post_type'], plugin_basename(__FILE__) ) ) return;
			}
			global $post;

			if( isset( $_POST ) && isset( $post->ID ) && get_post_type( $post->ID ) == $post_type_name )
			{
				global $custom_fields;

				// Loop through each meta box
				foreach( $custom_fields as $title => $fields )
				{
					// Loop through all fields
					foreach( $fields as $label => $type )				
					{
						$field_id_name 	= '_'.strtolower( str_replace( ' ', '_', $title ) ) . '_' . strtolower( str_replace( ' ', '_', $label ) );

						$value = isset($_POST['custom_meta'][$field_id_name]) ? $_POST['custom_meta'][$field_id_name] : ''; 

						$field_id_name 	= '_'.strtolower( str_replace( ' ', '_', $title ) ) . '_' . strtolower( str_replace( ' ', '_', $label ) );
						update_post_meta( $post->ID, $field_id_name, $value);

						
					
					}

				}
			}
				


		}


	}

}

?>