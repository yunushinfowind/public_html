function cm_tt_slider_shortcode_check(shortcode_id) {

	jQuery( document ).ajaxComplete(function() {

		jQuery('.ttshowcase_slider').fadeIn('slow');

		//slider wrapper
		var slider = jQuery(shortcode_id + '_cmpreview .ttshowcase_wrap');

		//check value of controls option
		var pager = false;
		var autocontrols = false;
		var controls = false;
		var nextselector = null;
		var prevselector = null;
		var nexttext = null;
		var prevtext = null;
		var auto = true;
		var adaptive = false;
		

		var controlsValue = jQuery(shortcode_id + '_slider #controls').val();
		var autov = jQuery(shortcode_id + '_slider #auto:checked').val();
		var adaptivev = jQuery(shortcode_id + '_slider #adaptive').val();

		

		if(autov!='on') {
			auto = false;
		}

		if(adaptivev == 'true') {
			adaptive = true;
		}

		console.log(adaptive);

		if(controlsValue=='pager') { pager = true } 
		if(controlsValue=='autocontrols') { autocontrols = true } 
		if(controlsValue=='controls') { 
			controls = true ;
			nextselector = shortcode_id + '_cmpreview #tt-slider-next';
		  	prevselector = shortcode_id + '_cmpreview #tt-slider-prev';
		  	nexttext = jQuery(shortcode_id + '_slider #controls-next').text();
		  	prevtext = jQuery(shortcode_id + '_slider #controls-prev').text();
		} 



		var spausetime = parseInt(jQuery(shortcode_id + '_slider #pause').val());
		var smode = jQuery(shortcode_id + '_slider #transition').val();

		var cmslider = slider.bxSlider({
		  mode: smode,
		  auto: auto,
		  controls: controls,
		  autoControls: autocontrols,
		  pager: pager,
		  pause: spausetime,
		  autoHover: true,
		  nextSelector: nextselector,
		  prevSelector: prevselector,
		  nextText: nexttext,
		  prevText: prevtext,
		  adaptiveHeight: adaptive
		  
		});

		if(auto==true) {
		jQuery('.bx-next, .bx-prev, .bx-pager a').click(function(){
				    // time to wait (in ms)
				    var wait = 2000;
				    setTimeout(function(){
				        cmslider.startAuto();
				    }, wait);
				});
		}

		
		
		cm_tt_shortcode_check();



		jQuery( document ).unbind('ajaxComplete');


	  
	});


}