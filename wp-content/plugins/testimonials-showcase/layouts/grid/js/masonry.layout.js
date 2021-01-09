jQuery(document).ready(function($){

		
		$('.ttshowcase_masonry').each(function() {
				var msnry = new Masonry( this, {
			  		itemSelector: '.ttshowcase_rl_box'
				});	

		});

});

var ttmasonryUpdate = function() {
   
   	 jQuery('.ttshowcase_masonry').masonry();


}