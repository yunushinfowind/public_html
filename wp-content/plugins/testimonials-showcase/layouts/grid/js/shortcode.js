
function cm_tt_shortcode_check(shortcode_id) {

	//When Ajax Loads
	jQuery( document ).ajaxComplete(function() {
	  
		jQuery(".tt_colorbox_iframe").colorbox({iframe:true, innerWidth:640, innerHeight:390, transition: 'fade'});

		if (typeof Masonry !== 'undefined') {

			var container = document.querySelector('.ttshowcase_wrap > div');
			
			if(container!=null) {


				var msnry = new Masonry( container, {
			  	itemSelector: '.ttshowcase_rl_box'
				});		

			}
			

		}

		jQuery( document ).unbind('ajaxComplete');
	  
	});

	
}


