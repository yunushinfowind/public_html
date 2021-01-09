<?php


class tt_front_form {

	//make it public so it can be accessed by cmshowcase constructor
	public $layout_id = 'form'; //should be same name as folder
	public $layout_name = 'Frontend Submission Form';
	public $settings;
	public $options;
	public $enqueue_files;
	public $shortcode_check; // js function to run for preview to work properly

	function __construct($id = ''){

		$this->showcase_id = $id;

		//Options for the Generator
		$options = array(

			'subtitle' => array(
				'label' => __('Subtitle','ttshowcase'),
				'description' => __('Subtitle input active','ttshowcase'),
				'type' => 'checkbox',
				'default' => 'on',
				'value' => 'on'
				),

			'subtitle_url' => array(
				'label' => __('URL field','ttshowcase'),
				'description' => __('URL input field active','ttshowcase'),
				'type' => 'checkbox',
				'default' => 'on',
				'value' => 'on'
				),

			'image' => array(
				'label' => __('Display Image Upload','ttshowcase'),
				'description' => __('Display Image Upload option','ttshowcase'),
				'type' => 'checkbox',
				'default' => 'off',
				'value' => 'on'
				),


			'review_title' => array(
				'label' => __('Display Title Option','ttshowcase'),
				'description' => __('Display Review/testimonial title option','ttshowcase'),
				'type' => 'checkbox',
				'default' => 'off',
				'value' => 'on'
				),


			'rating' => array(
				'label' => __('Display Star Rating','ttshowcase'),
				'description' => __('Display Star Rating option','ttshowcase'),
				'type' => 'select',
				'default' => 'on',
				'options' => array(
					'on' => 'Default (dropdown)',
					'hover' => 'Star Hover',
					'off' => 'Do not display'
					)
				),

			'email' => array(
				'label' => __('Email Field','ttshowcase'),
				'description' => __('Display Email Field','ttshowcase'),
				'type' => 'checkbox',
				'default' => 'on',
				'value' => 'on'
				),

			'verification' => array(
					'label' => __('Human Verification','ttshowcase'),
					'description' => __('Display math problem to verify if visitor is human. It will not display if user is logged in','ttshowcase'),
					'type' => 'select',
					'default' => 'off',
					'options' => array(
						'on' => __('Math Problem','ttshowcase'),
						'captcha' => __('Letter Deciphering','ttshowcase'),
						'off' => 'None'
					)
			),


			'logged' => array(
					'label' => __('Recognise Logged Users','ttshowcase'),
					'description' => __('If the user is logged, it will autofill email and name fields','ttshowcase'),
					'type' => 'checkbox',
					'default' => 'off',
					'value' => 'on'
			),


			'logged_only' => array(
					'label' => __('Only allow Logged Users','ttshowcase'),
					'description' => __('The form will only display if the user is logged in','ttshowcase'),
					'type' => 'checkbox',
					'default' => 'off',
					'value' => 'on'
			),


			
			

			'category' => array(
					'label' => __('Default Category','ttshowcase'),
					'description' => __('Hidden field to set default category for entry. Useful for product or service reviews.','ttshowcase'),
					'type' => 'taxonomy',
					'default' => '',
					'cpt' => 'ttshowcase',
					'none_label' => __('Do not use','ttshowcase'),
					'extra_options' => array(
								'{current_page_slug}' => __('[ Current Page Slug ]','ttshowcase'),
								'{current_page_id}' => __('[ Current Page ID ]','ttshowcase')
								)
					
			),

			'display_category' => array(
					'label' => __('Dispay category dropdown','ttshowcase'),
					'description' => __('The form will display a category dropdown for the user to choose the category. If a default category is set, it will display initially selected.','ttshowcase'),
					'type' => 'checkbox',
					'default' => 'off',
					'value' => 'on'
			),

			/*
			'boolean' => array(
					'label' => __('Dispay custom Yes/No','ttshowcase'),
					'description' => __('Will display the custom yes/no field','ttshowcase'),
					'type' => 'checkbox',
					'default' => 'off',
					'value' => 'on'
			),
			*/

			'style' => array(
				'label' => __('Style','ttshowcase'),
				'description' => __('Which style to adapt for the form','ttshowcase'),
				'type' => 'select',
				'default' => 'tt_simple',
				'options' => array(
					'none' => 'none (inherit styles)',
					'tt_simple' => 'Simple',
					'tt_style_1' => 'Style 1',
					'tt_style_2' => 'Style 2',
					'tt_style_3' => 'Style 3',
					'tt_style_4' => 'Style 4',
					)
				),


		);



		$this->options = $options; 

		//Files to enqueue on the generator and when building the layout

		$enqueue = array(
			'css' => array(
				'tt-form-style' => array(
					'file' => '/form/style.css'
					),
				
				'tt-hover-style' => array(
					'file' => '/form/hover-rating.css'
					),
				
				'tt-font-awesome' => array(
						'file' => '/resources/font-awesome/css/font-awesome.min.css'
					),
				)
			);
		
		$this->enqueue_files = $enqueue;
		
	}

}





?>