function tt_ajax_form() {

	/*

	This file is under development
	The current version of the plugin does not yet have ajax / jquery validation

	Possible Fields:
	postTitle
	subtitle
	url
	testimonial
	rating
	email
	review title
	image
	verification
	category_taxonomy
	post_status
	*/

	var data = {
		action: 'ttshowcase_ajax_form',
		message: 'Form Submitted'
	};
			
	jQuery.post(ajax_object.ajax_url, data, function(response) {
			
			jQuery('.ttshowcase_form_wrap').html(response);

	});

}