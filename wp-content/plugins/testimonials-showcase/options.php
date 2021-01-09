<?php
/*
Options Format:
$options = array (
	'names' => array(), 		//Names for the Custom Post Type 
	'addons' => array(),		//Addons for the Custom Post Type
	'args' => array(),			//Arguments to build the Custom Post Type
	'meta_boxes' => array(),	//Arguments to build Custom Meta Boxes for the CPT
	'taxonomies' => array(),	//Arguments to build taxonomies for the CPT
	'options' => array(),		//Arguments to build a options / settings page
)
*/

//Don't forget to use the __() function, when the content is translatable
//This way it will be easier for translation plugins to pick it up
$ttshowcase_options = array(

		//General names and slug for the custom post type
		//We set them outside the args to make it easier to control the labels with simple options
		//We use the __() function, when the content is translatable
		
		'names' => array(
			'singular' => __('Testimonial','ttshowcase'),
			'plural' => __('Testimonials','ttshowcase'),
			'slug' => 'testimonial'
		),

		//Array to set some options for how the CPT will display
		//to add extra options like custom thumbnail sizes or new columns on archive admin page

		'addons' => array(

			'thumb-sizes' => array(
				'normal' => array(
					'id' => 'normal',
					'width' => '200',
					'height' => '200',
					'crop' => false
				),
				'small' => array(
					'id' => 'small',
					'width' => '55',
					'height' => '55',
					'crop' => true
				)
			),

			'admin-archive-taxonomy-filter' => array(
				'taxonomies' => array('ttshowcase_groups'),
				'labels' => array(
					'show_all_label' => __('Show all','ttshowcase'),
					)
			),

			//this feature will add extra columns to the archive admin page
			'admin-archive-columns' => array(

				'testimonial' => array(
					'title' => __('Testimonials','ttshowcase'),
					'type' => 'text',
					'source' => array('aditional_info','short_testimonial'),
					'limit' => 150
				),

				'taxonomies' => array(
					'title' => __(cmshowcase_get_option('taxonomy','ttshowcase_basic_settings', 'Groups'),'ttshowcase'),
					'type' => 'taxonomy',
					'source' => 'ttshowcase_groups'
				),

				'featured_image' => array(
					'title' => __('Image','ttshowcase'),
					'type' => 'thumbnail',
					'source' => 'featured_image' 
					// source could be an array, if we want a custom field. Example: array('aditional_info','date')
				),
				/*
				'menu_order' => array(
					'title' => __('Order','ttshowcase'),
					'type' => 'order',
					'source' => 'menu_order'
				)
				*/
				
			),
			'move-editor-below' => array('postimagediv','aditional_info','case_study_info'),
			'single-page-filters' => array('ttshowcase_single_page'),
			'admin-entries' => 100,
			'vector-icon' => '/img/icon16.png',
			'font-icon' => '\f122',
			'single-template-filters' => array('ttshowcase_single_template')
		),

		//Arguments for the custom post type
	    //Reference: http://codex.wordpress.org/Function_Reference/register_post_type#Arguments

		'args' =>  array( 

			//Labels. Using wildcards to use previously defined names
			'labels' => array( 
		        'name' => __('%plural%','ttshowcase'),
		        'singular_name' => __('%singular%','ttshowcase'),
		        'all_items' => __('All %plural%','ttshowcase'),
		        'add_new' => __('Add New %singular%','ttshowcase'),
		        'add_new_item' => __('Add New %singular%','ttshowcase'),
		        'edit_item' => __('Edit %singular%','ttshowcase'),
		        'new_item' => __('New %singular%','ttshowcase'),
		        'view_item' => __('View %singular%','ttshowcase'),
		        'search_items' => __('Search','ttshowcase'),
		        'not_found' => __('No %singular% found','ttshowcase'),
		        'not_found_in_trash' => __('No %singular% found in Trash','ttshowcase'),
		        'parent_item_colon' => __('Parent %singular%:','ttshowcase'),
		        'menu_name' => __('%plural%', 'ttshowcase'),
		    ) ,
	        'hierarchical' => false,        
	        'supports' => array( 'title', 'thumbnail', 'custom-fields','page-attributes','editor'),
	        'public' => true,
	        'show_ui' => true,
	        'show_in_menu' => true,       
	        'show_in_nav_menus' => true,
	        'publicly_queryable' => true,
	        'exclude_from_search' => true,
	        'has_archive' => true,
	        'query_var' => true,
	        'can_export' => true,
	        'rewrite' => array('slug' => __('testimonial','ttshowcase')),
	        'capability_type' => 'post',
	        //'menu_icon' => plugins_url( 'img/icon.svg', __FILE__ ),
	        
 			),

		//Custom meta boxes to be created

		'meta_boxes' => array(

			'advanced_info' => array(
				'title' => __('Advanced URL Image Settings','ttshowcase'),
				'description' => __('Advanced Image URL settings for this entry','ttshowcase'),
				'context' => 'normal',
				'priority' => 'core',
				'fields' => array(

					'target' => array(
						'label' => __('Behavior','ttshowcase'),
						'type' => 'select',
						'description' => __('What behavior will the image have?','ttshowcase'),
						'default' => 'none',
						'options' => array(
							'none' => 'None',
							'read_more' => __('Link to Single Page Entry','ttshowcase'),
							'sub_title' => __('Same Link of Subtitle entry','ttshowcase'),
							/*'content' => __('Open entry content in default lightbox','ttshowcase'),*/
							'custom_url' => __('Open Custom Url in New Page','ttshowcase'),
							'custom_url_same' => __('Open Custom Url in Same Page','ttshowcase'),
							'custom_iframe' => __('Open Url in default lightbox','ttshowcase'),
							'custom_lightbox' => __('Open Url in custom lightbox','ttshowcase'),

							)
					) ,

					'custom_url' => array(
						'label' => __('URL','ttshowcase'),
						'type' => 'text',
						'description' => __('<br />Add the custom URL here, if the above selection requires you to do so.<br />
							If you have another lightbox plugin installed you can use the custom lightbox option and set the class in the advanced settings.<br />
							Use the default lightbox option with careful. If you have another lightbox plugin installed, they might be conflictual.<br />
							Read more about how to build links for the lightbox <a href="http://cmoreira.net/testimonials-showcase/lightbox" target="_blank">here</a>
							','ttshowcase'),
					) ,

					
				),

			),

			'case_study_info' => array(
					'title' => __('Extended Page Content','ttshowcase'),
					'description' => __('If the single page is active you can use the editor below to add content to the page. If you will not use the single page, you can leave the field blank.','ttshowcase'),
					'context' => 'normal',
					'priority' => 'high',
					'fields' => array()
				),

			'featured_image' => array(
				'title' => __('Featured Image for Testimonial','ttshowcase'),
				'context' => 'normal',
				'priority' => 'high',
				'preset' => 'featured_image' // we set the type of featured image to remove the image box if exists and add it again
			),

			'aditional_info' => array(
				'title' => __('Testimonial Info','ttshowcase'),
				'description' => __('Additional information for this entry','ttshowcase'),
				'context' => 'normal',
				'priority' => 'core',
				'fields' => array(
					'name' => array(
						'label' => __('Subtitle','ttshowcase'),
						'type' => 'text',
						'description' => __('<br />This will display below the Title of the entry. It could be for example the position or company of the author of this testimonial','ttshowcase'),
					) ,
					
			'designation' => array(
						'label' => __('Designation','ttshowcase'),
						'type' => 'text',
						'description' => __('<br />If you want to give a designation to author, you can add it here','ttshowcase'),
					) ,

					'url' => array(
						'label' => __('URL for subtitle','ttshowcase'),
						'type' => 'text',
						'description' => __('<br />If you want a link to be added to the sub-title above, you can add it here','ttshowcase'),
					) ,

					'target' => array(
						'label' => __('URL Target','ttshowcase'),
						'type' => 'select',
						'description' => __('Target to Open the URL','ttshowcase'),
						'options' => array(
							'_blank' => __('New page','ttshowcase'),
							'_blank_no_follow' => __('New page (no follow)','ttshowcase'),
							'_top' => __('Same Page','ttshowcase'),
							)
					) ,

					'review_title' => array(
						'label' => __('Title for short Testimonial','ttshowcase'),
						'type' => 'text',
						'description' => __('<br />Optional. Title to be added just before the testimonial/review text','ttshowcase'),
					) ,

					
					'short_testimonial' => array(
						'label' => __('Short Testimonial','ttshowcase'),
						'type' => 'wysiwyg',
						'description' => __('Short Testimonial Text','ttshowcase'),
					), 

					'rating' => array(
						'type' => 'select',
						'label' => __('Rating','ttshowcase'),
						'description' => __('Optional. Only to be used in the layout if choosen to. If you have the Rich Snippets option active in the settings it\'s recommended you insert a rating value','ttshowcase'),
						'default' => '0',
						'options' => array(
							'0' => __('Ignore','ttshowcase'),
							//'0.5' => __('0.5 Stars','ttshowcase'),
							'1' => __('1 Star','ttshowcase'),
							//'1.5' => __('1.5 Stars','ttshowcase'),
							'2' => __('2 Stars','ttshowcase'),
							//'2.5' => __('2.5 Stars','ttshowcase'),
							'3' => __('3 Stars','ttshowcase'),
							//'3.5' => __('3.5 Stars','ttshowcase'),
							'4' => __('4 Stars','ttshowcase'),
							//'4.5' => __('4.5 Stars','ttshowcase'),
							'5' => __('5 Stars','ttshowcase'),
							)
					),
					'email' => array(
						'label' => __('Email','ttshowcase'),
						'type' => 'text',
						'description' => __('For information purposes only. <br />This will not be displayed in the layout but it might be used to search for a Gravatar if the featured image is not set.','ttshowcase'),
					), 
					/*
					'custom_boolean' => array(
						'label' => cmshowcase_get_option('custom_boolean_label','ttshowcase_front_form', 'Yes or No field'),
						'type' => 'hidden',
						'description' => __('This field has no particular purpose, but can be used to grab more custom information from the users. Label can be defined in the Frontend form settings','ttshowcase'),
						'options' => array(
							'true' => __('Yes','ttshowcase'),
							'false' => __('No','ttshowcase'),
							)
					) ,
					*/
				),

			),
			
		),

		//custom taxonomies to be created
		
		'taxonomies' => array(
			'groups' => array(
				'names' => array(
					'singular' => __('Category','ttshowcase'),
					'plural' => __('Category','ttshowcase'),
					'slug' => 'testimonial-category'
				),
				'labels' => array(
				) ,
				'args' => array(
					'hierarchical' => true,
				) ,
				'fields' => array(

					

							/*
							
							'price' => array(
								'label' => __('Price','ttshowcase'),
								'description' => __('Testing Description','ttshowcase'),
								'type' => 'text',
							) ,

							'availability' => array(
								'label' => __('Availability','ttshowcase'),
								'description' => __('Testing Description','ttshowcase'),
								'type' => 'text',
							) ,

							*/

					
				) ,
			) ,
		) ,
	);


// We set the 'options' array separate as we will need to build it with the layouts.
// We could have it together also, in the main array under 'options'

/*
Special template array handled before
*/

$tt_template_options = array('post' => __('Post','ttshowcase'), 'page' => __('Page','ttshowcase'));

	$tt_templates = wp_get_theme()->get_page_templates();

	foreach ( $tt_templates as $template_name => $template_filename ) { 
	 $tt_template_options[$template_name] = $template_filename; 
	 }



$ttshowcase_settings = array(
			'settings' => array(
				'capability' => 'manage_options',
				'menu_title' => __('Settings','ttshowcase'),
				'page_title' => __('Settings','ttshowcase'),
				'sections' => array(
					'basic_settings' => array(
						'section_id' => 'basic_settings',
						'section_title' => __('Basic Settings','ttshowcase'),
						'section_description' => __('Basic settings for the plugin.','ttshowcase'),
						'section_order' => 1,
						'fields' => array(

							
							
							'naming' => array(
								'label' => __('<h4>Plugin Naming Related Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'singular' => array(
								'label' => __('Singular Name','ttshowcase'),
								'description' => __('Singular Name for Plugin Feature','ttshowcase'),
								'type' => 'text',
								'default' => 'Testimonial',
								'use_as' => 'singular',
								'size' => 'medium'
							) ,
							'plural' => array(
								'label' => __('Plural Name','ttshowcase'),
								'description' => __('Plural Name for Plugin Feature','ttshowcase'),
								'type' => 'text',
								'default' => 'Testimonials',
								'use_as' => 'plural',
								'size' => 'medium'
							) ,
							'taxonomy' => array(
								'label' => __('Category Menu Name','ttshowcase'),
								'description' => __('Menu Name for Category','ttshowcase'),
								'type' => 'text',
								'default' => 'Group',
								'use_as' => 'taxonomy_plural',
								'use_as_target' => 'groups',
								'size' => 'medium'
							) ,
							'slug' => array(
								'label' => __('Slug (url text)','ttshowcase'),
								'description' => __('Url String for This (You might need to re-save the permalink options after changing this setting)','ttshowcase'),
								'type' => 'text',
								'default' => 'testimonial',
								'use_as' => 'slug',
								'size' => 'medium'
							) ,

							
							'star_title' => array(
								'label' => __('<h4>Star Icon Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'empty_stars' => array(
								'label' => __('Display Empty stars','ttshowcase'),
								'description' => __('If active empty stars will display in 4 and below ratings, so 5 stars are always present','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'
							) ,

							
							'thumb-small' => array(
								'label' => __('<h4>Small Thumbnail Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'thumb-small-width' => array(
								'label' => __('Small Thumbnail Width','ttshowcase'),
								'description' => __('Thumbnail size in pixels','ttshowcase'),
								'type' => 'text',
								'default' => '75',
								'size' => 'small',
								'use_as' => 'thumb_size_width',
								'use_as_target' => 'small'
							) ,
							'thumb-small-height' => array(
								'label' => __('Small Thumbnail Height','ttshowcase'),
								'description' => __('Thumbnail size in pixels','ttshowcase'),
								'type' => 'text',
								'default' => '75',
								'size' => 'small',
								'use_as' => 'thumb_size_height',
								'use_as_target' => 'small'
							) ,
							'thumb-small-crop' => array(
								'label' => __('Small Thumbnail Crop','ttshowcase'),
								'description' => __('Do you want the thumbnail to be cropped when uploaded?','ttshowcase'),
								'type' => 'select',
								'options' => array(
									'true' => __('Yes','ttshowcase'),
									'false' => __('No','ttshowcase')
								),
								'default' => 'false',
								'use_as' => 'thumb_size_crop',
								'use_as_target' => 'small'
							) ,

							'thumb-normal' => array(
								'label' => __('<h4>Normal Thumbnail Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'thumb-normal-width' => array(
								'label' => __('Thumbnail Width','ttshowcase'),
								'description' => __('Thumbnail size in pixels','ttshowcase'),
								'type' => 'text',
								'default' => '125',
								'size' => 'small',
								'use_as' => 'thumb_size_width',
								'use_as_target' => 'normal'
							) ,
							'thumb-normal-height' => array(
								'label' => __('Thumbnail Height','ttshowcase'),
								'description' => __('Thumbnail size in pixels','ttshowcase'),
								'type' => 'text',
								'default' => '125',
								'size' => 'small',
								'use_as' => 'thumb_size_height',
								'use_as_target' => 'normal'
							) ,
							'thumb-normal-crop' => array(
								'label' => __('Thumbnail Crop','ttshowcase'),
								'description' => __('Do you want the thumbnail to be cropped when uploaded?','ttshowcase'),
								'type' => 'select',
								'options' => array(
									'true' => __('Yes','ttshowcase'),
									'false' => __('No','ttshowcase')
								),
								'default' => 'false',
								'use_as' => 'thumb_size_crop',
								'use_as_target' => 'normal'
							) ,
							'single_page_title' => array(
								'label' => __('<h4>Single Page Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,
							/*
							'single_page_info' => array(
								'label' => __('Display Testimonial Info','ttshowcase'),
								'description' => __('If active the testimonial info such as author and rating will display','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'value' => 'on'
							) ,
							*/
							'single_page_testimonial' => array(
								'label' => __('Display short testimonial','ttshowcase'),
								'description' => __('If active the testimonial entry will also display in the single page','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'value' => 'on'
							) ,

							'single_page_template' => array(
								'label' => __('Theme Template','ttshowcase'),
								'description' => __('<br>The way this option works will also depend on your theme. The default template is the Post template, but many themes display extra meta information on post pages such as "posted by" or "post date" information, which may not be desired. Usually, page templates contain the essential information. If you choose "Pages" then the testimonials will be shown using your theme default page template. <storng>Be aware that some themes will not work with this option</strong>, if so (or you want to make a custom page), you can create a file named <code>single-ttshowcase.php</code> <a href="http://codex.wordpress.org/Post_Types#Template_Files">as shown on the wordpress codex</a>, and leave this set to Posts.','ttshowcase'),
								'type' => 'select',
								'default' => 'post',
								'type' => 'select',
								'options' => $tt_template_options,
							) ,

							'pagination' => array(
								'label' => __('<h4>Pagination Labels Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'next' => array(
								'label' => __('Next Label','ttshowcase'),
								'description' => __('Next Page link label','ttshowcase'),
								'type' => 'text',
								'default' => 'Next Page',
								'size' => 'medium'
							) ,
							'previous' => array(
								'label' => __('Previous Label','ttshowcase'),
								'description' => __('Previous page link label','ttshowcase'),
								'type' => 'text',
								'default' => 'Previous Page',
								'size' => 'medium'
							) ,
							'date_settings' => array(
								'label' => __('<h4>Date Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,

							'date_format' => array(
								'label' => __('Date Format','ttshowcase'),
								'description' => __('Date format for the testiminials layouts, when displayed','ttshowcase'),
								'type' => 'radio',
								'default' => 'default',
								'options' => array(
									'' => __('WordPress Default','ttshowcase'),
									'l, F j, Y' => 'Friday, September 24, 2004',
									'Y/m/d' => '2004/09/24',
									'd/m/Y' => '24/09/2004',
									'human' => 'Human Readable Format. Example: 24 days ago',
									'custom' => 'Custom (insert format below)'
									)
							) ,
							'custom_date_format' => array(
								'label' => __('Custom Date Format','ttshowcase'),
								'description' => __('Documentation here: http://codex.wordpress.org/Formatting_Date_and_Time','ttshowcase'),
								'type' => 'text',
								'default' => 'd-m-Y',
								'size' => 'medium'

							)
							

						),

					),

					'rich_snippets' => array(
						'section_id' => 'rich_snippets',
						'section_title' => __('Rich Snippets','ttshowcase'),
						'section_description' => __('<a href="https://support.google.com/webmasters/answer/99170" target="_blank">Rich Snippets</a> provide meta data about your page to the search engines. <br />
														If you are using the STAR RATING option for your entries, you can activate the Rich Snippets so Review or Aggregate Review information will be included in the code. <br />
														The code will follow the <a href="http://schema.org/" target="_blank">Schema.org</a> formats.','ttshowcase'),
						'section_order' => 5,
						'fields' => array(

							'intro_info' => array(
								'label' => __('<strong>Attention!</strong>','ttshowcase'),
								'description' => __('Rich Snippets will work better if only 1 shortcode on the page will render the metadata. If there are multiple aggregate ratings metadata, rich snippets will not work as expected. <a href="http://cmoreira.net/testimonials-showcase/rich-snippets/" target="_blank">More information about this</a>. <br> You can override the settings below via shortcode also.','ttshowcase'),
								'type' => 'html'
							) ,

							'single_page_active' => array(
								'label' => __('Activate Rich Snippets in single pages','ttshowcase'),
								'description' => __('If active Schema.org Review data will be added to the single page for the entries','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'
							) ,

							'shortcode_active' => array(
								'label' => __('Activate Rich Snippets in shortcodes','ttshowcase'),
								'description' => __('If active Schema.org Aggregate Review data will be added to the layouts generated by shortcodes','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'
							) ,

							'product_info' => array(
								'label' => __('<strong>Product or Service being reviewed</strong>','ttshowcase'),
								'description' => __('The search engines need to know what is being reviewed. Use one of the two options below to define what product or service is being reviewed. In addition, you can also set a custom product/service name for each layout you create with the shortcode generator.','ttshowcase'),
								'type' => 'html'
							) ,


							'categories_as_products' => array(
								'label' => __('Use Groups as products','ttshowcase'),
								'description' => __('Enable this option if you want the plugin to interpret the categories as products to include the information on the Rich Snippets. It will only work when the layout created is only displaying entries from a specific category. The default entry defined below will be ignored.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'
							) ,

							'default_product' => array(
								'label' => __('Default Product name','ttshowcase'),
								'description' => __('Default product name to be used in the rich snippets information, in case the categories are off or do not exist, or the product information for the entry is empty.','ttshowcase'),
								'type' => 'text',
								'default' => get_bloginfo()
							) ,
							'schema' => array(
								'label' => __('Schema.org type','ttshowcase'),
								'description' => __('The default is http://schema.org/Product but you can use other schema.org types.','ttshowcase'),
								'type' => 'text',
								'default' => 'http://schema.org/Product'
							) ,
							'schema_logo' => array(
								'label' => __('Logo','ttshowcase'),
								'description' => __('Specify the image path of your logo.','ttshowcase'),
								'type' => 'text',
								'default' => ''
							) ,
							'schema_telephone' => array(
								'label' => __('Telephone'),
								'description' => __('Specify Telephone No.','ttshowcase'),
								'type' => 'text',
								'default' => ''
							) ,
							'schema_business_address' => array(
								'label' => __('Address'),
								'description' => __('Specify Full Businness Address.','ttshowcase'),
								'type' => 'text',
								'default' => ''
							) ,

							'adv_rich_snippets' => array(
								'label' => __('Display advanced options in Shortcode Generator','ttshowcase'),
								'description' => __('If enabled, more options will display in the shortcode generator, in the Rich Snippets section.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'
							) ,

						)
					),

					
					'front_form' => array(
						'section_id' => 'front_form',
						'section_title' => __('Front-End Form','ttshowcase'),
						'section_description' => __('This settings will reflect in the shortcodes you create to display the front-end submission form.','ttshowcase'),
						'section_order' => 4,
						'fields' => array(

							
							'labels' => array(
								'label' => __('<h4>Field Labels</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,
							'name_label' => array(
								'label' => __('Name Label','ttshowcase'),
								'description' => __('Text to display for the title input','ttshowcase'),
								'type' => 'text',
								'default' => 'Name',
								'size' => 'medium'
							) ,
							'subtitle_label' => array(
								'label' => __('Subtitle Label','ttshowcase'),
								'description' => __('Text to display for the subtitle information input','ttshowcase'),
								'type' => 'text',
								'default' => 'Position or Company',
								'size' => 'medium'
							) ,
							'url_label' => array(
								'label' => __('URL Label','ttshowcase'),
								'description' => __('Text to display for the URL input','ttshowcase'),
								'type' => 'text',
								'default' => 'URL',
								'size' => 'medium'
							) ,
							'review_title_label' => array(
								'label' => __('Testimonial Title Label','ttshowcase'),
								'description' => __('Text to display for the Testimonial Title input option','ttshowcase'),
								'type' => 'text',
								'default' => 'Title',
								'size' => 'medium'
							) ,
							'testimonial_label' => array(
								'label' => __('Testimonial Label','ttshowcase'),
								'description' => __('Text to display for the Testimonial textarea option','ttshowcase'),
								'type' => 'text',
								'default' => 'Testimonial',
								'size' => 'medium'
							) ,
							'rating_label' => array(
								'label' => __('Rating Label','ttshowcase'),
								'description' => __('Text to display for the Rating option','ttshowcase'),
								'type' => 'text',
								'default' => 'Rate',
								'size' => 'medium'
							) ,

							'star_singular' => array(
								'label' => __('Rating Type Singular Label','ttshowcase'),
								'description' => __('Text to display for singular rating identification (ex.: Star)','ttshowcase'),
								'type' => 'text',
								'default' => 'Star',
								'size' => 'medium'
							) ,

							'star_plural' => array(
								'label' => __('Rating Type Plural Label','ttshowcase'),
								'description' => __('Text to display for singular rating identification (ex.: Stars)','ttshowcase'),
								'type' => 'text',
								'default' => 'Stars',
								'size' => 'medium'
							) ,
							'default_rating' => array(
								'label' => __('Default Rating','ttshowcase'),
								'description' => __('Initial selected rating value','ttshowcase'),
								'type' => 'select',
								'default' => '5',
								'options' => array(
									'0' => __('0','ttshowcase'),
									//'0.5' => __('0.5 Stars','ttshowcase'),
									'1' => __('1','ttshowcase'),
									//'1.5' => __('1.5 Stars','ttshowcase'),
									'2' => __('2','ttshowcase'),
									//'2.5' => __('2.5 Stars','ttshowcase'),
									'3' => __('3','ttshowcase'),
									//'3.5' => __('3.5 Stars','ttshowcase'),
									'4' => __('4','ttshowcase'),
									//'4.5' => __('4.5 Stars','ttshowcase'),
									'5' => __('5','ttshowcase'),
									)
							) ,

							'email_label' => array(
								'label' => __('Email Label','ttshowcase'),
								'description' => __('Text to display for the Email input','ttshowcase'),
								'type' => 'text',
								'default' => 'Email',
								'size' => 'medium'
							) ,
							

							'verification' => array(
								'label' => __('Human Verification Label','ttshowcase'),
								'description' => __('Text to display for Human math problem verification','ttshowcase'),
								'type' => 'text',
								'default' => 'Are you Human?',
								'size' => 'medium'
							) ,
							

							'image_label' => array(
								'label' => __('Image Label','ttshowcase'),
								'description' => __('Text to display for the Image input','ttshowcase'),
								'type' => 'text',
								'default' => 'Image',
								'size' => 'medium'
							) ,

							'category_label' => array(
								'label' => __('Category Label','ttshowcase'),
								'description' => __('Text to display for the category dropdown input','ttshowcase'),
								'type' => 'text',
								'default' => 'Category',
								'size' => 'medium'
							) ,
							/*
							'custom_boolean_label' => array(
								'label' => __('Custom Yes/No Field Label','ttshowcase'),
								'description' => __('Text to display for the Yes/No dropdown field.','ttshowcase'),
								'type' => 'text',
								'default' => 'Yes or No?',
								'size' => 'medium'
							) ,
							*/

							'submit_label' => array(
								'label' => __('Submit Button Label','ttshowcase'),
								'description' => __('Text to display on the submit button','ttshowcase'),
								'type' => 'text',
								'default' => 'Submit Entry',
								'size' => 'medium'
							) ,

							'messages' => array(
								'label' => __('<h4>Confirmation and Email Settings </h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,
							'thankyou' => array(
								'label' => __('Thank You Message','ttshowcase'),
								'description' => __('Text to display after the user submits the form. Will only display if the "Confirmation Page" field is empty.','ttshowcase'),
								'type' => 'wysiwyg',
								'default' => __('Thank you for submitting your testimonial! It is now awaiting approval from the site administrator. Thank you!','ttshowcase'),
							) ,

							'thankyou_url' => array(
								'label' => __('Confirmation Page','ttshowcase'),
								'description' => __('If you want the user to be redirected to a specific URL instead of displaying the above message, place the URL here. If there is an URL in this field the message above will be ignored and the user will be redirected to the page you have set here.','ttshowcase'),
								'type' => 'text',
								'default' => __('','ttshowcase'),
							) ,
							'force_redirect' => array(
								'label' => __('Force Page Refresh','ttshowcase'),
								'description' => __('If active and the confirmation page URL does not exist, the submission page will refresh, displaying both the success message and the form again. This takes more resources, but could be usefull when using the testimonials layout on the same page with auto-approval.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on',
							) ,
							'error' => array(
								'label' => __('Error Message','ttshowcase'),
								'description' => __('Message to display when an error occurs.' ,'ttshowcase'),
								'type' => 'wysiwyg',
								'default' => __('The entry was not submitted. Check the form for errors.','ttshowcase'),
							) ,
							'loggedonly' => array(
								'label' => __('Non-logged users message','ttshowcase'),
								'description' => __('Message to display to non logged users if you make the form available only to logged users' ,'ttshowcase'),
								'type' => 'wysiwyg',
								'default' => __('You need to be a registered user to submit entries.','ttshowcase'),
							) ,
							'human_verification_logged' => array(
								'label' => __('Human Verification on logged users','ttshowcase'),
								'description' => __('If active, the human control field, if chosen to display, will also display to logged users','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'value' => 'on',
							) ,
							'honeypot_spam' => array(
								'label' => __('Honeypot Spam prevention','ttshowcase'),
								'description' => __('If active, a hidden field will be included in the form, that should be empty on submission. If it has a value, it most likely means the form is being submitted by a robot.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'value' => 'on',
							) ,
							'akismet' => array(
								'label' => __('Use Akismet','ttshowcase'),
								'description' => __('When enabled, Akismet will be used to filter the valid submissions. If they are considered spam they will be stored, but in the trash, they will not be published and they won\'t trigger the notification email. This will only work if you have Akismet plugin enabled with a valid API key.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on',
							) ,
							'sendemail' => array(
								'label' => __('Send Notification Email','ttshowcase'),
								'description' => __('Send new entry notification email to site administrator','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'value' => 'on',
							) ,
							'email_to' => array(
								'label' => __('Send Email to','ttshowcase'),
								'description' => __('Notification email will be sent to this address','ttshowcase'),
								'type' => 'text',
								'default' => get_option( 'admin_email' ),
							) ,
							'email_subject' => array(
								'label' => __('Notification Email Subject','ttshowcase'),
								'description' => __('Notification email subject','ttshowcase'),
								'type' => 'text',
								'default' => __('New Testimonial for Review','ttshowcase'),
							) ,
							'email_message' => array(
								'label' => __('Notification Email Message','ttshowcase'),
								'description' => __('Message to be sent when new testimonial has been submited. Template tags can be used:<br> {title} - Name of entry author<br>{admin_url} - Link to the edit and approval page for this entry<br> {text} - Entry submitted text<br> {rating} - Rating for this entry','ttshowcase'),
								'type' => 'wysiwyg',
								'default' => __('New Testimonial entry from: {title}. <br /> <a href="{admin_url}">Approve or Delete Entry</a>','ttshowcase'),
							) ,

							'publish_info' => array(
								'label' => __('<h4>Publish Status Settings</h4>','ttshowcase'),
								'description' => __('','ttshowcase'),
								'type' => 'html',
							) ,
							'status' => array(
								'label' => __('Default Status of Submissions','ttshowcase'),
								'description' => __('<br>Chose if you want the entries to be automatically published or to stay pending review, until the admin decides to publish them','ttshowcase'),
								'type' => 'select',
								'default' => 'pending',
								'options' => array(
									'pending' => __('Pending Review - Administrator will need to approve entry','ttshowcase'),
									'publish' => __('Published - Entries will be automatically visible','ttshowcase')
								)
							) ,
						)
					),
					'advanced_settings' => array(
						'section_id' => 'advanced_settings',
						'section_title' => __('Advanced Settings','ttshowcase'),
						'section_description' => __('Advanced settings for the plugin.','ttshowcase'),
						'section_order' => 10,
						'fields' => array(

							'custom_css' => array(
								'label' => __('Custom CSS','ttshowcase'),
								'description' => __('Add custom CSS here. It will be added to the page where the layout will display','ttshowcase'),
								'type' => 'textarea',
								
							) ,

							

							'custom_js' => array(
								'label' => __('Custom JS','ttshowcase'),
								'description' => __('Add custom javascript code here. It will be added to the page where the layouts will display','ttshowcase'),
								'type' => 'textarea',
								
							) ,

							'load_css_form' => array(
								'label' => __('Load Custom CSS & JS for Forms','ttshowcase'),
								'description' => __('If active, the above custom CSS and javascript will also load on pages where the frontend submission form is being used','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
								'value' => 'on'

							) ,

							'exclude-from-search' => array(
								'label' => __('Exclude from Search','ttshowcase'),
								'description' => __('Exclude entries from general search results','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
								'use_as' => 'exclude_from_search',

							) ,

							'use_gravatar' => array(
								'label' => __('Use Gravatar','ttshowcase'),
								'description' => __('If entry doesn\'t have a featured image but has an email, the plugin will check with the Gravatar service if there is a profile image set for that email.','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
							) ,
							'force_aspect_ratio' => array(
								'label' => __('Force Height Output','ttshowcase'),
								'description' => __('Some avatar images might not output the height parameter. If you want to force the height parameter to display, check this box. Will use more server load (to calculate proper image height)','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
							) ,

							'render_shortcodes' => array(
								'label' => __('Render Shortcodes','ttshowcase'),
								'description' => __('If disabled shortcodes won\'t be rendered inside the testimonials text entries','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'on',
							) ,

							'render_smiles' => array(
								'label' => __('Render Smiles','ttshowcase'),
								'description' => __('If enabled and the emoticons are also enabled on "Settings > Writting > Formatting" it will convert emoticons like :-) and :-P to graphics on display','ttshowcase'),
								'type' => 'checkbox',
								'default' => 'off',
							) ,

							'custom_lightbox' => array(
								'label' => __('Custom Lightbox Class attribute','ttshowcase'),
								'description' => __('If you are using a custom lightbox plugin, place here the class name the links should have so the lightbox initiates.','ttshowcase'),
								'type' => 'text',
								'size' => 'medium',
								'default' => '',
							) ,
							'custom_lightbox_rel' => array(
								'label' => __('Custom Lightbox rel attribute','ttshowcase'),
								'description' => __('If you are using a custom lightbox plugin, place here the content for the attribute rel="" the links should have so the lightbox initiates.','ttshowcase'),
								'type' => 'text',
								'size' => 'medium',
								'default' => '',
							) ,
							'quote_elements' => array(
								'label' => __('Elements of Quote block','ttshowcase'),
								'description' => __('Which elements to display inside quote block (Inside Speech Bubble).<br> Available template tags: {quote},{read_more},{review_title},{author},{stars},{date},{subtitle},{category}','ttshowcase'),
								'type' => 'text',
								'size' => 'regular',
								'default' => '{review_title}{quote}{read_more}'
								),

							'info_elements' => array(
								'label' => __('Elements of Info block','ttshowcase'),
								'description' => __('Which elements to display inside info block (Together with Image).<br> Available template tags: {quote},{read_more},{review_title},{author},{stars},{date},{subtitle},{category}','ttshowcase'),
								'type' => 'text',
								'size' => 'regular',
								'default' => '{author}{subtitle}{stars}{category}{date}'
								),
							'single_page_shortcode' => array(
								'label' => __('Render Shortcode Layout on Single Page','ttshowcase'),
								'description' => __('If you want to render for example a speech bubble layout on the single page, inclue the "options:" parameter of a shortcode here. For example:<br>
									theme:speech,info-position:info-left,text-alignment:left,columns:1,display-image:on,image-size:ttshowcase_small,image-shape:circle,image-effect:none,image-link:on','ttshowcase'),
								'type' => 'text',
								'default' => '',
								'size' => 'regular'
							) ,
						)
					),
					'help_settings' => array(
						'section_id' => 'help',
						'section_title' => __('Help! FAQ','ttshowcase'),
						'section_description' => __('If you\'re having any problem with the plugin you can read the full list of Frequently asked questions in the <a href="http://codecanyon.net/item/testimonials-showcase-wordpress-plugin/6588139/support" target="_blank">Official FAQ page of the plugin</a>. <h3>CSS Tips & Tricks</h3> You can also check some CSS tips on the <a href="http://cmoreira.net/testimonials-showcase/custom-css/" target="_blank">official plugin site</a>.<br><br> <h2>The read more link / single page entry are not working! What can I do?</h2><br>If when you open a single page it returns a "Page Not Found" error, it\'s possible that the permalinks are not working well. Go on Settings > Permalinks and save the settings again, even without any changes. This will make the permalinks option update.<br><br>Another possible problem is conflict of slugs. If you have a page with the same ‘slug’ (permalink name) of the Testimonials Showcase (default is "testimonials"), the single pages might not work properly. You will have to change or the slug of the page/post or the slug of the Testimonials Showcase entries, in the plugin settings page and resave the permalinks again. <br> <br> ','ttshowcase'),
						'section_order' => 11
					)
				)
			)	
		);

// Layouts Array
// Simple array with layout folder names
// Built seperatity to be easy to manipulate

$ttshowcase_layouts = array(
	'grid' => array(
		'class' => 'cm_tt_grid',
	),
	'slider' => array(
		'class' => 'cm_tt_slider'
		),
	/*'averagebox' => array(
		'class' => 'tt_average_box'
		),*/
	
); 


// SHORTCODES ARRAY
/*
Format: 
'layout' = array ()			// Layouts available
'generator' => array()		// Shortcode Generator Page options
'shortcodes' => array()		// Shortcodes and callbaks to be built
*/

$ttshowcase_shortcodes = array(

		'layouts' => $ttshowcase_layouts,

		'generator' => array(
			'capability' => 'manage_options',
			'menu_title' => __('Shortcode Generator','ttshowcase'),
			'page_title' => __('Shortcode Generator','ttshowcase'),	
			//'intro_text' => __('This could be used to describe the generator','ttshowcase'),
			'pre_nav_label' => __('Available Generators:','ttshowcase'),
			'post_type' => array('ttshowcase'),
			'generators' => array(
				'show-testimonials-simple' => array(
					'title' => __('Layout: Simple Query','ttshowcase'),
					'description' => __('This will generate a layout for the Testimonials. You have some simple options to perform a query to choose which entries to display','ttshowcase'),
					'shortcode' => 'show-testimonials',
					'type' => 'layout',
					'callback' => 'ttshowcase_show_testimonials',
					'labels' => array(
						'query' => __('What you want to display','ttshowcase'),
						'layout' => __('How you want to display it','ttshowcase'),
						'shortcode' => __('You can use the shortcode on your post, pages and text widgets','ttshowcase'),
						'php' => __('This is a php function to run this shortcode. You can use it directly in the Theme files','ttshowcase'),
						'shortcode_title' => __('Shortcode','ttshowcase'),
						'preview_title' => __('Preview','ttshowcase'),
						'preview_description' => __('This is a preview only. Once you place the shortcode on your page, it might look different since it will be integrated with your layout and some CSS of your theme or other plugins might affect the way the layout looks like.','ttshowcase'),
						'preview_light_bg' => __('Light Background','ttshowcase'),
						'preview_dark_bg' => __('Dark Background','ttshowcase')
						),
					'supports' => array(
						'taxonomy' => array(
							'label' => 'Taxonomy', // Taxonomy will default to taxonomy name
							'description' => __('Display entries only of this group.','ttshowcase'),
							'extra_options' => array(
								'{current_page_slug}' => __('[ Current Page Slug ]','ttshowcase'),
								'{current_page_id}' => __('[ Current Page ID ]','ttshowcase')
								)
						),
						'orderby' => array(
							'label' => __('Order By','ttshowcase'),
							'description' => __('Paramater to order the entries with','ttshowcase')
						),
						'limit' => array(
							'label' => __('Limit','ttshowcase'),
							'description' => __('Number of entries to display. Leave blank or 0 to display all.','ttshowcase'),
							'default' => ''
						),
						'pagination' => array(
							'label' => __('Pagination','ttshowcase'),
							'description' => __('Display pagination Below the layout (Limit number of entries should be set above)','ttshowcase'),
							'default' => 'off'
						),
					),

				),
				'show-testimonials-advanced' => array(
					'title' => __('Layout: Advanced Query','ttshowcase'),
					'description' => __('Advanced Shortcode Generator. You have more advanced options to perform a query to choose which entries to display','ttshowcase'),
					'shortcode' => 'show-testimonials',
					'callback' => 'ttshowcase_show_testimonials',
					'type' => 'layout',
					'labels' => array(
						'query' => __('What you want to display','ttshowcase'),
						'layout' => __('How you want to display it','ttshowcase'),
						'shortcode' => __('You can use the shortcode on your post, pages and text widgets','ttshowcase'),
						'php' => __('Click here to get the PHP function. You can use it directly in the Theme files','ttshowcase'),
						'shortcode_title' => __('Shortcode','ttshowcase'),
						'preview_title' => __('Preview','ttshowcase'),
						'preview_description' => __('This is a preview only. Once you place the shortcode on your page, it might look different since it will be integrated with your layout and some CSS of your theme or other plugins might affect the way the layout looks like.','ttshowcase'),
						),
					'supports' => array(
						'taxonomy_multiple' => array(
							'label' => __('Select Multiple','ttshowcase'),
							'description' => __('Select which categories to display','ttshowcase'),
							'extra_options' => array(
								'{current_page_slug}' => __('[ Current Page Slug ]','ttshowcase'),
								'{current_page_id}' => __('[ Current Page ID ]','ttshowcase')
								)
							),
						'limit' => array(
							'label' => __('Limit','ttshowcase'),
							'description' => __('Number of entries to display. Leave blank or 0 to display all.','ttshowcase'),
							'default' => ''
						),
						'pagination' => array(
							'label' => __('Pagination','ttshowcase'),
							'description' => __('Display pagination Below the layout (Limit number of entries should be set above)','ttshowcase'),
							'default' => 'off'
						),
						'orderby' => array(
							'label' => __('Order By','ttshowcase'),
							'description' => __('Paramater to order the entries with','ttshowcase')
						),
						'id_filter' => array(
							'label' => __('IDs to display','ttshowcase'),
							'description' => __('Comma sperated ID values of specific entries you want to display. Example: 7,11. Leave blank or 0 to display all','ttshowcase'),
							'default' => ''
						),
						'search' => array(
							'label' => __('Search for term','ttshowcase'),
							'description' => __('Search for a term in the title and content of the entry. Leave blank to ignore this field.','ttshowcase'),
						),
						'search_total' => array(
							'label' => __('Extensive Search for term','ttshowcase'),
							'description' => __('Search for a term in the title, content and all aditional information fields. Leave blank to ignore this field.','ttshowcase'),
						),
						'post_status' => array(
							'label' => __('Publish Status','ttshowcase'),
							'description' => __('Publish status of entries','ttshowcase'),
						)
					),

				),
				'show-form-testimonials' => array(
					'title' => __('Front-end Submission Form','ttshowcase'),
					'description' => __('Shortcode generator to display a front-end submission form. After generating the shortcode you can place it in a page and forward your users there to submit their own entries.','ttshowcase'),
					'shortcode' => 'show-testimonials-form',
					'callback' => 'ttshowcase_show_form',
					//In case of custom generators, we need to pass more values, so it knows where to grab info
					'type' => 'custom',
					'class' => 'tt_front_form',
					'src' => '/form/form-class.php',
					'labels' => array(
						'query' => __('What you want to display','ttshowcase'),
						'layout' => __('How you want to display it','ttshowcase'),
						'shortcode' => __('You can use the shortcode on your post, pages and text widgets','ttshowcase'),
						'php' => __('Click here to get the PHP function. You can use it directly in the Theme files','ttshowcase'),
						'shortcode_title' => __('Shortcode','ttshowcase'),
						'preview_title' => __('Preview','ttshowcase'),
						'preview_description' => __('This is a preview only. The forms might look slightly different when applied to your page. Usually the themes have their own form styles and when you place the shortcode in your page, the form might inherit the available form styles from your theme.','ttshowcase')
					),
				),
				'show-average-rating' => array(
					'title' => __('Average Rating Info','ttshowcase'),
					'description' => __('This will generate a layout for the Testimonials. You have some simple options to perform a query to choose which entries to display','ttshowcase'),
					'shortcode' => 'show-average-rating',
					'type' => 'custom',
					'class' => 'tt_average_box',
					'src' => '/layouts/averagebox/layout.php',
					'callback' => 'ttshowcase_average_rating',
					'labels' => array(
						'query' => __('What you want to display','ttshowcase'),
						'layout' => __('How you want to display it','ttshowcase'),
						'shortcode' => __('You can use the shortcode on your post, pages and text widgets','ttshowcase'),
						'php' => __('Click here to get the PHP function. You can use it directly in the Theme files','ttshowcase'),
						'shortcode_title' => __('Shortcode','ttshowcase'),
						'preview_title' => __('Preview','ttshowcase'),
						'preview_description' => __('This is a preview only. Once you place the shortcode on your page, it might look different since it will be integrated with your layout and some CSS of your theme or other plugins might affect the way the layout looks like.','ttshowcase'),
						'preview_light_bg' => __('Light Background','ttshowcase'),
						'preview_dark_bg' => __('Dark Background','ttshowcase')
						),
					'supports' => array(
						'taxonomy' => array(
							'label' => 'Taxonomy', // Taxonomy will default to taxonomy name
							'description' => __('Display entries only of this group.','ttshowcase'),
							'extra_options' => array(
								'{current_page_slug}' => __('[ Current Page Slug ]','ttshowcase'),
								'{current_page_id}' => __('[ Current Page ID ]','ttshowcase')
								)
						),
						'orderby' => array(
							'label' => __('Order By','ttshowcase'),
							'description' => __('Paramater to order the entries with','ttshowcase')
						),
						'limit' => array(
							'label' => __('Limit','ttshowcase'),
							'description' => __('Number of entries to display','ttshowcase'),
							'default' => 0
						),
					),

				),

			)		
		),
		'shortcodes' => array(
			'show-testimonials' => array(
				'id' => 'show-testimonials',
				'callback' => 'ttshowcase_show_testimonials',
			),
			'show-testimonials-form' => array(
				'id' => 'show-testimonials-form',
				'callback' => 'ttshowcase_show_form',
			)
			,
			'show-average-rating' => array(
				'id' => 'show-average-rating',
				'callback' => 'ttshowcase_average_rating',
			)
		)
		
	);

$ttshowcase_widgets = array(
	'layout' => array(
		'class' => 'ttshowcase_layout_widget',
		'file' => 'ttshowcase-layout-widget.php'
		)
	);


// We add the next array only to make it easier for translation plugins to grab the translatable content
// changing the content here will not take any effect
$ttshowcase_localization = array(
	'order_attribute' => __('Order Attribute','ttshowcase'),
	'id' => __('ID','ttshowcase'),
	'title' => __('Title','ttshowcase'),
	'random' => __('Random','ttshowcase'),
	'ascending' => __('Ascending','ttshowcase'),
	'descending' => __('Descending','ttshowcase'),
	'all' => __('All','ttshowcase'),
	'none' => __('None','ttshowcase'),
	'published' => __('Published','ttshowcase'),
	'pending_review' => __('Pending Review','ttshowcase'),
	'in_draf' => __('in Draft','ttshowcase'),
	'private' => __('Private','ttshowcase'),
	'asc' => __('ASC','ttshowcase'),
	'desc' => __('DESC','ttshowcase'),
	'updated_settings' => __('Settings Updated','ttshowcase'), 
	'continue_reading' => __('Continue Reading','ttshowcase'),
	'form_name' => __('Name','ttshowcase'),
	'form_position' => __('Position','ttshowcase'),
	'form_company' => __('Company','ttshowcase'),
	'form_url' => __('URL','ttshowcase'),
	'form_testimonial_label' => __('Testimonial','ttshowcase'),
	'form_rating' => __('Rating','ttshowcase'),
	'form_rate' => __('Rate','ttshowcase'),
	'form_email' => __('Email','ttshowcase'),
	'form_thank_you' => __('Thank you for submitting your message!'),
	'form_error' => __('The testimonial was not submitted. Check the form for errors.'),
	'form_submit' => __('Submit','ttshowcase'),
	'form_testimonial_title' => __('Testimonial Title','ttshowcase'),
	'form_image' => __('Your Image','ttshowcase'),
	'form_star' => __('Star','ttshowcase'),
	'form_stars' => __('Stars','ttshowcase'),
	'form_human' => __('Are you Human?','ttshowcase'),
	'form_category' => __('Category','ttshowcase'),
	'form_registred' => __('You need to be a registred user to submit entries'),
	'form_control' => __(' Please insert the correct answer','ttshowcase'),
	'form_error_name' => __(' Please enter a valid name','ttshowcase'),
	'form_valid_email' => __(' Please enter a valid email','ttshowcase'),
	'form_message_email_subject' => __('New Testimonial to Review','ttshowcase'),
	'form_valid_testimonial' => __(' Please enter a valid testimonial','ttshowcase')
	);

?>