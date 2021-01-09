/*
Main Function to build shortcode
*/

function cmshowcase_init() {

	//If Generator tabs exist, we add the current state to the first
	jQuery('#cm-nav-wrapper span.cm-nav-tab:first').addClass('cm-nav-tab-current');

}


function cmshowcase_build_shortcode(generator) {

	var shortcode_id;

	if(typeof(generator) === 'object') {

		shortcode_id = '#'+generator.form.id;

	} else {
		shortcode_id = '#'+generator;
	}

	var shortcode = jQuery( shortcode_id + " #shortcode" ).val();

	var fieldValuePairs = jQuery(shortcode_id).serializeArray();
	var shortcodedata = "";

	var fname = '';

	jQuery.each(fieldValuePairs, function(index, fieldValuePair) {

		if(fieldValuePair.value!='' && fieldValuePair.value!='0' && fieldValuePair.value!='off') {

			fieldValuePair.value = fieldValuePair.value.replace(' ','&nbsp;');

			if(fname == fieldValuePair.name) {
		     	shortcodedata = shortcodedata.substring(0, shortcodedata.length - 2) + ',' + fieldValuePair.value + "' ";
		     	fname = fieldValuePair.name;
				}

			 if(fname != fieldValuePair.name) {
		     	shortcodedata += fieldValuePair.name + "='" + fieldValuePair.value + "' ";
		     	fname = fieldValuePair.name;
				}
		 }

	});

	//Get the layout value and check the form with that value
	var layout = jQuery( shortcode_id + " #layout" ).val();
	var lstring = shortcode_id+'_'+layout;
	var layoutValuePairs = jQuery(lstring).serializeArray();

	//build options for layout
	var layoutopts = "";
	jQuery.each(layoutValuePairs, function(index, layoutValuePair) {


		// checks if option value if on
		if(layoutValuePair.value!='off' && layoutValuePair.value!='') {

			//checks if name of field has the 'hidden' so it wont be added to shortcode
			if(layoutValuePair.name.indexOf("hidden") == -1) {

				var name = layoutValuePair.name;

				//var value = layoutValuePair.value.replace(":","&#58;");
				var value = layoutValuePair.value.replace(":","##");
				value = value.replace(",","&#44;");
				value = value.replace(/'/g,"\"");

				layoutopts += name + ":" + value + ",";

			}

	     }

	});

	var options = '';

	if(layoutopts!='') {
	layoutopts = layoutopts.slice(0, -1);
	options = "options='"+layoutopts+"'";
	}

	var composed = "["+shortcode.trim()+" " + shortcodedata.trim() + " " + options.trim() + "]";

	//we use a different one, to count the number of layouts created in the page
	var gen_count = jQuery(shortcode_id +' #gen_count').val();
	var torender = "["+shortcode+" " + shortcodedata + " " + options + " counter='"+gen_count+"' preview='true' ]";


	jQuery(shortcode_id+'_cmshortcode #cmsctxt').val(composed);
	jQuery(shortcode_id+'_cmshortcode #cmphptxt').val('<?php echo do_shortcode("'+composed+'"); ?>');


	// To render the Preview

	console.log(shortcode_id);

	var preview_div = jQuery(shortcode_id+'_cmpreview');

	preview_div.html('Loading...');

	var data = {
			action: 'cmshowcase',
			shortcode: torender
		};
		
	jQuery.post(ajax_object.ajax_url, data, function(response) {
			preview_div.html(response);

			// We check if there is any callback to perform, from layouts
			var cal = jQuery(lstring+' #layoutcallback').val();
			if(cal != '') {
				if (typeof window[cal] === "function") {
					jQuery(document).ready(function($){
						window[cal](shortcode_id);
						console.log('layout callback run > '+cal);
					});
				}
			} 

		});


	
		
}

function cmshowcase_save_shortcode(generator) {

	var shortcode_id;

	if(typeof(generator) === 'object') {

		shortcode_id = '#'+generator.form.id;

	} else {
		shortcode_id = '#'+generator;
	}

	//var shortcode_text = jQuery('#'+generator+'_cmshortcode #cmloadtxt').val();
	var shortcode = jQuery('#'+generator+'_cmshortcode #cmsctxt' ).val();
	var new_name = jQuery('#'+generator+'_cmshortcode #new_shortcode' ).val();
	var saved_shortcodes = jQuery('#'+generator+'_cmshortcode #cmshowcase_saved_shortcodes' );
	var shortcode_trigger = jQuery( shortcode_id + " #shortcode" ).val();
	var override_name = jQuery('#'+generator+'_cmshortcode #cmshowcase_override_shortcode_name' );
	var over_name = 'null';

	if(override_name.val() == 'null' && new_name=='') {
		alert('Alias Name cannot be empty');
		return;
	}

	if(override_name.val()) {
		over_name = override_name.val();
	}
	
	console.log(new_name + ':' + shortcode);

	var data = {
			action: 'cmshowcase_save_shortcode',
			shortcode: shortcode,
			generator: generator,
			name: new_name,
			shortcode_trigger: shortcode_trigger,
			override_name: over_name
		};
		
	jQuery.post(ajax_object.ajax_url, data, function(response) {
			

			saved_shortcodes.html(response);

			//If it's a new value, we add it to the dropdown
			if(over_name == 'null' && new_name != '') {

				override_name.append(jQuery('<option>', {
				    value: new_name,
				    text: new_name
				}));

				override_name.val(new_name);
				cmshowcase_override_option(generator);

			}			

			jQuery('#'+generator+'_cmshortcode #save_shortcode_alias').addClass('button-primary');

			var message_div = jQuery('#'+generator +'_sctxt .cmshowcase_message_area');

			message_div.show();

			message_div.html('<div class="updated">Shortcode Saved!</div>');

			message_div.delay(4000).fadeOut('slow');



		});



}



function cmshowcase_view_shortcodes(generator) {

	var shortcode_id;

	if(typeof(generator) === 'object') {

		shortcode_id = '#'+generator.form.id;

	} else {
		shortcode_id = '#'+generator;
	}

	var saved_shortcodes = jQuery('#'+generator+'_cmshortcode #cmshowcase_saved_shortcodes' );

	var shortcode_trigger = jQuery( shortcode_id + " #shortcode" ).val();

	var data = {
			action: 'cmshowcase_view_shortcodes',
			generator: generator,
			shortcode_trigger: shortcode_trigger
		};
		
	jQuery.post(ajax_object.ajax_url, data, function(response) {
			saved_shortcodes.html(response);

		});

}

function cmshowcase_load_shortcode_saved(generator,alias) {

	

	var data = {
			action: 'cmshowcase_load_shortcode',
			generator: generator,
			name: alias
		};
		


	jQuery.ajax( ajax_object.ajax_url, {
        data: data,
        type: 'post',
        success: function(response) {
           	jQuery('#'+generator+'_cmshortcode #cmloadtxt').val(response);
			console.log('response shortcode received');

        },
        error: function(xhr,status,error) {
           // error code here
        },
        complete: function(xhr,status) {
           
			cmshowcase_load_shortcode(generator);
			//console.log('load shortcode triggered');

			jQuery('#'+generator+'_cmshortcode #cmshowcase_override_shortcode_name' ).val(alias);
			cmshowcase_override_option(generator);

			jQuery('#'+generator+'_cmshortcode #save_shortcode_alias').addClass('button-primary');

        }
   });


}

function cmshowcase_delete_shortcode_saved(generator,alias,message) {


	if (confirm(message)) {

		console.log('entry deleted');
		var shortcode_trigger = jQuery( '#'+generator + " #shortcode" ).val();

		var saved_shortcodes = jQuery('#'+generator+'_cmshortcode #cmshowcase_saved_shortcodes' );

		var data = {
				action: 'cmshowcase_delete_shortcode',
				generator: generator,
				name: alias,
				shortcode_trigger:shortcode_trigger
			};
			
		jQuery.post(ajax_object.ajax_url, data, function(response) {
			saved_shortcodes.html(response);
			jQuery('#'+generator+'_cmshortcode #cmshowcase_override_shortcode_name option[value="'+alias+'"]' ).remove();

		});
	} 

}

function cmshowcase_override_option(generator) {

	var new_name = jQuery('#'+generator+'_cmshortcode #new_shortcode' );
	var override_name = jQuery('#'+generator+'_cmshortcode #cmshowcase_override_shortcode_name' ).val();

	if(override_name != 'null') {
		new_name.prop('disabled', true);
		new_name.hide('slide');
		
	}

	else {
		new_name.prop('disabled', false);
		new_name.show('slide');
	}

}

/*
Function to hide/display the layout options
*/

function cmshowcase_display_layout_options(elt) {

	var form = elt.form.id + '_' +  elt.value;

	var formobj = document.getElementById(form);

	var generator_id = formobj.generatorid.value;

	jQuery('#'+generator_id+'_layout_options form').hide();
	
	var e = document.getElementById(form);
        e.style.display = 'block';

	cmshowcase_build_shortcode(generator_id);

}

function cmshowcase_display_layout_options_load(form) {


	var generator_id = '#'+form;

	jQuery(generator_id+'_layout_options form').hide();

	var layout = jQuery(generator_id + ' #layout').val();
	
	jQuery(generator_id+'_'+layout).show();

	cmshowcase_build_shortcode(form);

}


function cmshowcase_show_generator(div) {

	jQuery('#ttwrap > div').hide();

	var e = document.getElementById(div);
        e.style.display = 'block';

    jQuery('#cm-nav-wrapper > span.cm-nav-tab').removeClass('cm-nav-tab-current');

    var nav = div.replace('_wrapper','');
    	nav = nav+'_nav';

     jQuery('#'+nav).addClass('cm-nav-tab-current');
        

}

function cmshowcase_shortcode(generator,elm) {

	var ul = jQuery('#'+elm.id).parent().attr('id');
	jQuery('#'+generator+'_wrapper #'+ul+ ' > li').removeClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_wrapper #'+elm.id).addClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_sctxt').show();
	jQuery('#'+generator+'_phptxt').hide();
	jQuery('#'+generator+'_loadtxt').hide();

}

function cmshowcase_shortcode_php(generator,elm) {

	var ul = jQuery('#'+elm.id).parent().attr('id');
	jQuery('#'+generator+'_wrapper #'+ul+' > li').removeClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_wrapper #'+elm.id).addClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_sctxt').hide();
	jQuery('#'+generator+'_phptxt').show();
	jQuery('#'+generator+'_loadtxt').hide();

}

function cmshowcase_shortcode_load_menu(generator,elm) {

	var ul = jQuery('#'+elm.id).parent().attr('id');
	jQuery('#'+generator+'_wrapper #'+ul+' > li').removeClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_wrapper #'+elm.id).addClass('cm_shortcode_nav_current');
	jQuery('#'+generator+'_sctxt').hide();
	jQuery('#'+generator+'_phptxt').hide();
	jQuery('#'+generator+'_loadtxt').show();

}

function cmshowcase_load_shortcode(generator) {

	var shortcode_text = jQuery('#'+generator+'_cmshortcode #cmloadtxt').val();

	shortcode = jQuery('#'+generator+ " #shortcode" ).val();
	
	
	var form_id = '#'+generator;
	
	var regex = new RegExp( '\\[(\\[?)(' + shortcode + ')(?![\\w-])([^\\]\\/]*(?:\\/(?!\\])[^\\]\\/]*)*?)(?:(\\/)\\]|\\](?:([^\\[]*(?:\\[(?!\\/\\2\\])[^\\[]*)*)(\\[\\/\\2\\]))?)(\\]?)', 'g' );

 	var shortcode_bolean = regex.test(shortcode_text);

	if(!shortcode_bolean) {
		alert('Invalid Shortcode for this Generator.');
	}

	if(shortcode_bolean) {
		
		//Get the shortcode via regex
		var regex_2 = new RegExp( '\\[(\\[?)(' + shortcode + ')(?![\\w-])([^\\]\\/]*(?:\\/(?!\\])[^\\]\\/]*)*?)(?:(\\/)\\]|\\](?:([^\\[]*(?:\\[(?!\\/\\2\\])[^\\[]*)*)(\\[\\/\\2\\]))?)(\\]?)', 'g' );
		var match = regex_2.exec(shortcode_text);
		//console.log(match[3]);
		//transform it in the first array
		var opts = match[3].trim().split("' ");
		var optsarray = [];

		//transform it in the proper options array
		for (var i=0;i<opts.length;i++)
		{ 
			if(opts[i]!='') {
				var temp = opts[i].trim().split('=');
				//remove quotes
				var tempvalue = temp[1].trim();
				tempvalue = tempvalue.substring(1, tempvalue.length);
				tempvalue = tempvalue.replace("'","");
				optsarray[temp[0]] = tempvalue;		

			}
			
		}

		console.log(optsarray);

		//get the form fields
		var fieldValuePairs = jQuery(form_id).serializeArray();

		//we have the optsarray and fieldValuePairs to match
		cmshowcase_match_fields(fieldValuePairs,optsarray,form_id);


		//If there is a 'options' parameter, we check the layout form
		

		if('layout' in optsarray) {

			console.log('The layout exists: ' + optsarray['layout']);
			
			if( 'options' in optsarray ) {

				console.log('The options exists: ' + optsarray['options']);

				//we get the form fields
				var layout_form_id = '#'+generator+'_'+optsarray['layout'];
				var layout_form = jQuery(layout_form_id).serializeArray();

				//we parse the options
				var lopts = optsarray['options'].trim().split(",");
				var loptsarray = [];

				for (var i=0;i<lopts.length;i++)
				{ 
					if(lopts[i]!='') {
						var ltemp = lopts[i].split(':');
						//remove quotes
						var ltempvalue = ltemp[1].trim();
						loptsarray[ltemp[0]] = ltempvalue;		

					}
					
				}

				//So now we have the layout_form and the loptsarray variables to match
				cmshowcase_match_fields(layout_form,loptsarray,layout_form_id);

				
			}

			//and we check if the layout options form need to be displayed:
			cmshowcase_display_layout_options_load(generator);

		}


		//console.log('Current Form: '+form_id);
		

		

		//change tab to shortcode
		btn = new Object();
		btn.id= generator +'_shortcode_sc';

		cmshowcase_shortcode(generator,btn);

		var message_div = jQuery('#'+generator +'_sctxt .cmshowcase_message_area');

		message_div.show();

		message_div.html('<div class="updated">Shortcode Loaded!</div>');

		message_div.delay(4000).fadeOut('slow');

		//run shortcode generator
		cmshowcase_build_shortcode(generator);

	}

}

function cmshowcase_match_fields(fieldValuePairs,optsarray,form_id) {

	var othis, type, thisval;
	
	for (var i=0;i<fieldValuePairs.length;i++)
	{ 

		othis = jQuery(form_id+" #"+fieldValuePairs[i].name);
		type = othis.prop("tagName") == 'INPUT' ? othis.prop("type").toLowerCase() : othis.prop("tagName").toLowerCase();

		if( fieldValuePairs[i].name in optsarray ) {

			
		   
		   	//if it's text or select
		   	if(type!='checkbox') {
	   			
	   			thisval = optsarray[fieldValuePairs[i].name];
	   			
	   			if(type=='select') {
	   				
	   				thisval = thisval.split(',')
	   			}	

	    		othis.val( thisval );

	    		console.log(fieldValuePairs[i].name+':'+type+':'+othis.val());

		   	} 
			//if it's a checkbox
		   	else {
		   		console.log(fieldValuePairs[i].name+':'+type+':checked');
	    		othis.attr('checked', true);
		   	}	    

		}
		else { 

			//if it's text or select
		   	if(type!='checkbox') {

		   		thisval = '';

		   		if(type=='select') {
	   				thisval = ['none','off',0];
	   			}	

	   			console.log(fieldValuePairs[i].name+':'+type+':Null');
	    		othis.val( thisval );

		   	} 
			//if it's a checkbox
		   	else {
		   		console.log(fieldValuePairs[i].name+':'+type+':unchecked');
		   		othis.attr('checked', false);
	    		//othis.val( optsarray[fieldValuePairs[i].name] );
		   	}	  
		}
	}



}


function cmshowcase_shortcode_preview_l(generator,elm) {
	var ul = jQuery('#'+elm.id).parent().attr('id');
	jQuery('#'+ul+' > li').removeClass('cm_preview_toggle_current');
	jQuery('#'+elm.id).addClass('cm_preview_toggle_current');

	jQuery('#'+generator+'_cmpreview').removeClass('cmshowcase_dark_cmpreview');
	jQuery('#'+generator+'_cmpreview').addClass('cmshowcase_light_cmpreview');
	
}

function cmshowcase_shortcode_preview_d(generator,elm) {
	var ul = jQuery('#'+elm.id).parent().attr('id');
	jQuery('#'+ul+' > li').removeClass('cm_preview_toggle_current');
	jQuery('#'+elm.id).addClass('cm_preview_toggle_current');

	jQuery('#'+generator+'_cmpreview').removeClass('cmshowcase_light_cmpreview');
	jQuery('#'+generator+'_cmpreview').addClass('cmshowcase_dark_cmpreview');

}

function cmshowcase_shortcode_to_php(div,info) {

	var value = jQuery('#'+div+' textarea').val();

	if(value.indexOf("do_shortcode") == -1) {
	jQuery('#'+div+' textarea').val('<?php do_shortcode("'+value+'"); ?>');
	jQuery('#'+info).addClass('cm_shortcode_nav_current');
	} 
	else {
		var strip = value.replace('<?php do_shortcode("','');
			strip = strip.replace('"); ?>','');
		jQuery('#'+div+' textarea').val(strip);
		jQuery('#'+info).addClass('cm_shortcode_nav_current');
	}
}

cmshowcase_init();
