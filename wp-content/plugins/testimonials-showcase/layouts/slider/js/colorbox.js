jQuery(document).ready(function($){

	/*
	for (var key in tt_colorbox_params) {

	var identifier = tt_colorbox_params[key]['id'];
	var type = tt_colorbox_params[key]['type'];
	var ifstatus = false;
	var inlstatus = false;

	if(type=='iframe') {
		ifstatus = true;
	}

	if(type=='inline') {
		inlstatus = true;
	}



	$("."+identifier).colorbox({iframe:ifstatus, inline:inlstatus, innerWidth:640, innerHeight:390, transition: 'fade'});

	}
	*/
 
		jQuery(".tt_colorbox_iframe").colorbox({iframe:true, innerWidth:'90%', maxWidth:640, maxHeight:390, innerHeight:'90%', transition: 'fade'});
		jQuery(".tt_colorbox_inline").colorbox({iframe:false, inline:true, innerWidth:640, innerHeight:390, transition: 'fade'});

});


