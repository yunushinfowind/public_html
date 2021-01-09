
function cm_tt_colorbox_shortcode_check(shortcode_id) {

	jQuery( document ).ajaxComplete(function() {
	  
		jQuery(".tt_colorbox_iframe").colorbox({iframe:true, innerWidth:640, innerHeight:390, transition: 'fade'});
		jQuery(".tt_colorbox_inline").colorbox({iframe:false, inline:true, innerWidth:640, innerHeight:390, transition: 'fade'});

		jQuery( document ).unbind('ajaxComplete');
	  
	});
	
}
