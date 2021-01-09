<?php
/*

Last Modified: July 4th 2015
Author: Carlos Moreira

*/


/*
Function to merge the array of options of layouts with the array of settings 
to build the custom post type settings page
*/

if (!function_exists('cmshowcase_build_layout_options')) {

	function cmshowcase_build_layout_options($layouts,$options) {

		if (is_array($layouts)) {

					foreach ($layouts as $key => $value) {

						require_once dirname( __FILE__ ) . '/../layouts/'.$key.'/layout.php';

						$constructor = $value['class'];

						$layout = new $constructor(null);

						if($layout->settings) {
							$options['settings']['sections'][$layout->layout_id] = $layout->settings;
						}

						//to clear some memory
						unset($layout);
					}

		} 

		return $options;

	}
}

if (!function_exists('cmshowcase_extract_options')) {

	function cmshowcase_extract_options($options) {

			$opt = str_replace(":", "=", $options);
			$opt = str_replace(",", "&", $opt);
			$opt = html_entity_decode($opt);

			parse_str($opt, $return);
			
        
		return $return;
	}
}



/*
Function to build the query with the available atts from a shortcode or widget
*/
if (!function_exists('cmshowcase_build_query')) {

	function cmshowcase_build_query($cpt,$opts) {
		
		$args = array(
			'post_type' => $cpt,
			//'suppress_filters' => true
		);


		//Author Paramaters
		if(isset($opts['author'])) {
			$args['author'] = $opts['author'];
		}

		//Category Parameters
		if(isset($opts['category'])) {
			$args['category'] = $opts['category'];
		}

		//Tags Parameters
		if(isset($opts['tags'])) {
			$args['tag'] = $opts['tag'];
		}


		//Taxonomy Parameters
		//Currently only works if only 1 taxonomy exists
		if(isset($opts['taxonomy'])) {

			$taxonomies = get_object_taxonomies($cpt , 'names');

			//Special Placeholders for special categories
			if($opts['taxonomy'] == '{current_page_slug}' || $opts['taxonomy'] == '{current_page_id}') {

				if($opts['taxonomy'] == '{current_page_slug}') {

					$slug = basename(get_permalink());
					$args[$taxonomies[0]] = $slug;
					
				}

				if($opts['taxonomy'] == '{current_page_id}') {

					$this_post = get_post();
					if(is_object($this_post)) {
						$current_page_id = $this_post->ID;
					} else {
						$current_page_id = 'null';
					}
					$args[$taxonomies[0]] = $current_page_id;
					
				}
				
			}

			else {

				
			
				/*
				
				$taxarray = array();
				//$taxarray = array('relation' => 'OR'

				foreach ($taxonomies as $tax => $value) {
					$current_tax = array(
					'taxonomy' => $value, // get taxonomy 
					'field' => 'slug',
					'terms' => $opts['taxonomy'],
					);

					array_push($taxarray, $current_tax);
				}
				$args['tax_query'] = $taxarray;
				*/


				$args[$taxonomies[0]] = $opts['taxonomy'];

			}

		}
		

		


		//Post&Page Paramaters
		if(isset($opts['id_filter'])) {
			if($opts['id_filter']!=''){
			$args['post__in'] = explode(',',$opts['id_filter']);
			}
		}

		//Status Parameters
		$args['post_status'] = 'publish';
		if(isset($opts['post_status'])) {
			$args['post_status'] = $opts['post_status'];
		}
		
		//Pagination Parameters
			//limit posts

		if(isset($opts['limit'])) {
			$args['posts_per_page'] = $opts['limit'];
			$args['nopaging'] = false;
		} else { 
			$args['posts_per_page'] = -1;
			$args['nopaging'] = true;
			}

			//pagination
		if(isset($opts['pagination'])) {
			$paged = 1;

			//we build a unique identifier
			$queryval = substr($cpt,0,2).'page';

			if(isset($_GET[$queryval])){ $paged = $_GET[$queryval];}
			$args['paged'] = $paged;
		} 

		//Order Parameters
		if(isset($opts['orderby'])) {
			remove_all_filters('posts_orderby');
			$args['orderby'] = $opts['orderby'];

			//if we order by custom numeric meta
			
			if (strlen(strstr($opts['orderby'],'num'))>0) {
				
				$args['orderby'] = 'meta_value_num';

				$meta = explode('|',$opts['orderby']);

				if(isset($meta[1])) {
					$args['meta_key'] = $meta[1];
				}
				

			}

			


		} 

		if(isset($opts['order'])) {
			$args['order'] = $opts['order'];
		} else {
			$args['order'] = 'ASC';
		}

		//Date Parameters
		//Nothing for now

		//Custom Fields Parameters
		//Nothing for now

		//Search Paramaters
		if(isset($opts['stotal'])) {
			
			//If Custom Fields Search ON
			//We perform a new query

			$args['meta_value'] = $opts['stotal'];
			$args['meta_compare'] = "LIKE";

			$cf_query = new WP_Query( $args );
			wp_reset_postdata();

			unset($args['meta_value']);
			unset($args['meta_compare']);

			// ^ End custom fields search 

			$args['s'] = $opts['stotal'];
	
		}

		if(isset($opts['s'])) {

			//normal search for title and content
			$args['s'] = $opts['s'];
	
		}

		//random fix
		
		if(isset($opts['orderby']) && $opts['orderby']=='rand') {
			$args['orderby'] = 'date';
			$args['posts_per_page'] = -1;
			$args['nopaging'] = true;
		}
		


		$query = new WP_Query( $args );


		 //Random Fix
		if(isset($opts['orderby']) && $opts['orderby']=='rand') {

			shuffle( $query->posts );

			if(isset($opts['limit'])) {
			$query->post_count = $opts['limit'];
			}

		}
		


		//We check again if the search parameter exists to merge arrays
		//Merge If Search is ON

		if(isset($opts['stotal'])) {
			$query->posts = $cf_query->posts+$query->posts ;
			$query->post_count = count($query->posts);
		}


		wp_reset_postdata();

		return $query;

	}
}

if (!function_exists('cmshowcase_build_shortcode_field_taxonomy')) {

	function cmshowcase_build_shortcode_field_taxonomy($cpt,$options) {


		$taxonomies = get_object_taxonomies($cpt,'object');
		
		foreach ($taxonomies as $tax) {

			$args = array();
			$args['id'] = 'taxonomy'; //str_replace($cpt.'_','',$tax->query_var);
			$args['default'] = '';
			$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Display entries only of the selected category';
			$args['size'] = 'medium';
			$args['onchange'] = 'cmshowcase_build_shortcode(this)';
			$args['default'] = isset($options['default']) ? $options['default'] : '0';
			$args['tax_args'] = isset($options['tax_args']) ? $options['tax_args'] : array(
                'orderby'       => 'name', 
                'order'         => 'ASC',
                'hide_empty'    => false
            );

            $args['extra_options'] = isset($options['extra_options']) ? $options['extra_options'] : false;

			$terms = get_terms( $tax->query_var , $args['tax_args'] );

			$count = count($terms);
			$optarray = array();
			$optarray['0'] = __('All',$cpt);

			if ($count > 0 && !isset($terms->errors)) {
				foreach($terms as $term) {
					$optarray[$term->slug] = $term->name;				
				}
			}

			
			if($args['extra_options']) {

				foreach ($args['extra_options'] as $key => $value) {
					$optarray[$key] = __($value,$cpt);
				}	
			
			}

			$args['options'] = $optarray;

			echo "<tr><td class='cmshowcase_field_label'>".$tax->labels->menu_name."</td> \n ";
			echo "<td>";
			cmshowcase_build_field_select( $args );
			echo "</td></tr> \n";
			
		}

	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_taxonomy_multiple')) {

	function cmshowcase_build_shortcode_field_taxonomy_multiple($cpt,$options) {


		$taxonomies = get_object_taxonomies($cpt,'object');
		
		foreach ($taxonomies as $tax) {

			$args = array();
			$args['id'] = 'taxonomy'; //str_replace($cpt.'_','',$tax->query_var);
			$args['default'] = '';
			$args['description'] = isset($options['description']) ? $options['description'] : 'Display entries only of the selected category';
			$args['size'] = 'medium';
			$args['onchange'] = 'cmshowcase_build_shortcode(this)';
			$args['default'] = isset($options['default']) ? $options['default'] : '0';
			$args['multiple'] = true;
			$args['tax_args'] = isset($options['tax_args']) ? $options['tax_args'] : array(
                'orderby'       => 'name', 
                'order'         => 'ASC',
                'hide_empty'    => false
            );

            $args['extra_options'] = isset($options['extra_options']) ? $options['extra_options'] : false;

			$terms = get_terms( $tax->query_var , $args['tax_args']);
			$count = count($terms);
			$optarray = array();
			$optarray['0'] = __('All',$cpt);
			if ($count > 0 && !isset($terms->errors)) {
				foreach($terms as $term) {
					$optarray[$term->slug] = $term->name;
				}
			}

			if($args['extra_options']) {

				foreach ($args['extra_options'] as $key => $value) {
					$optarray[$key] = __($value,$cpt);
				}	
			
			}
			

			$args['options'] = $optarray;

			echo "<tr><td class='cmshowcase_field_label'>".$tax->labels->menu_name."</td> \n ";
			echo "<td>";
			cmshowcase_build_field_select( $args );
			echo "</td></tr> \n";
			
		}

	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_limit')) {

	function cmshowcase_build_shortcode_field_limit($cpt,$options) {

		$args = array();
		$args['id'] = 'limit';
		$args['default'] = isset($options['default']) ? $options['default'] : '0';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Parameter to order the entries';
		$args['size'] = 'small';
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_text( $args );
		echo "</td></tr> \n";


	} 

}


if (!function_exists('cmshowcase_build_shortcode_field_search')) {

	function cmshowcase_build_shortcode_field_search($cpt,$options) {

		$args = array();
		$args['id'] = 's';
		$args['default'] = isset($options['default']) ? $options['default'] : '';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Search for term';
		$args['size'] = 'medium';
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_text( $args );
		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_search_total')) {

	function cmshowcase_build_shortcode_field_search_total($cpt,$options) {

		$args = array();
		$args['id'] = 'stotal';
		$args['default'] = isset($options['default']) ? $options['default'] : '';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Search for term in all fields';
		$args['size'] = 'medium';
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_text( $args );
		echo "</td></tr> \n";


	} 

}


if (!function_exists('cmshowcase_build_shortcode_field_id_filter')) {

	function cmshowcase_build_shortcode_field_id_filter($cpt,$options) {

		$args = array();
		$args['id'] = 'id_filter';
		$args['default'] = isset($options['default']) ? $options['default'] : '';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Parameter to order the entries';
		$args['size'] = 'medium';
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_text( $args );
		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_orderby')) {

	function cmshowcase_build_shortcode_field_orderby($cpt,$options) {

		$args = array();
		$args['id'] = 'orderby';
		$args['default'] = isset($options['default']) ? __($options['default'],$cpt) : 'menu_order';
		$args['description'] = '';
		$args['options'] = array(
			'menu_order' => __('Order Attribute',$cpt),
			'id' => __('ID',$cpt),
			'rand' => __('Random',$cpt), 
			'title' => __('Title',$cpt),
			'date' => __('Date',$cpt),
			//ttshowcase_specific
			'num|_aditional_info_rating' => __('Rating',$cpt)

		);
		$args['size'] = 'medium';
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_select( $args );

		$args = array();
		$args['id'] = 'order';
		$args['default'] = 'ASC';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'Parameter to order the entries';
		$args['options'] = array(
			'ASC' => __('Ascending',$cpt),
			'DESC' => __('Descending',$cpt) 
		);
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';
		cmshowcase_build_field_select( $args );

		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_post_status')) {

	function cmshowcase_build_shortcode_field_post_status($cpt,$options) {

		$args = array();
		$args['id'] = 'post_status';
		$args['default'] = isset($options['default']) ? $options['default'] : 'publish';
		$args['description'] = isset($options['description']) ? $options['description'] : '';
		$args['options'] = array(
			'publish' => __('Published',$cpt), 
			'pending' => __('Pending Review',$cpt), 
			'draft' => __('in Draft',$cpt), 
			'private' => __('Private',$cpt)
		);
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_select( $args );
		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_pagination')) {

	function cmshowcase_build_shortcode_field_pagination($cpt,$options) {

		$args = array();
		$args['id'] = 'pagination';
		$args['default'] = isset($options['default']) ? $options['default'] : 'off';
		$args['description'] = isset($options['description']) ? $options['description'] : '';
		$args['options'] = array(
			'off' => __('Do Not Use',$cpt), 
			'on' => __('Use Pagination',$cpt),
			'short' => __('Use Pagination (Short)',$cpt)
		);
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_select( $args );
		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_build_shortcode_field_order')) {

	function cmshowcase_build_shortcode_field_order($cpt,$options) {

		$args = array();
		$args['id'] = 'order';
		$args['default'] = 'ASC';
		$args['description'] = isset($options['description']) ? __($options['description'],$cpt) : 'How to order the entries';
		$args['options'] = array(
			'ASC' => __('ASC',$cpt),
			'DESC' => __('DESC',$cpt) 
		);
		$args['onchange'] = 'cmshowcase_build_shortcode(this)';

		echo "<tr><td class='cmshowcase_field_label'>".__($options['label'],$cpt)."</td> \n ";
		echo "<td>";
		cmshowcase_build_field_select( $args );
		echo "</td></tr> \n";


	} 

}

if (!function_exists('cmshowcase_enqueue_layout_scripts')) {

	function cmshowcase_enqueue_layout_scripts($files) {

	    if($files!=false) {

	        if(isset($files['css'])) {
	            foreach ($files['css'] as $key => $value) {

	                $id = $key;
	                $file = $value['file'];
	                $dependencies = isset($value['dependencies']) ? $value['dependencies'] : array();
	                $version = isset($value['version']) ? $value['version'] : false;
	                $media = isset($value['media']) ? $value['media'] : 'all';

	                wp_deregister_style( $key );
	                wp_register_style( $key, plugins_url( $file , dirname(__FILE__)) , $dependencies , $version, $media);
	                wp_enqueue_style( $key );
	                
	            }
	        }

	        if(isset($files['javascript'])) {
	            foreach ($files['javascript'] as $key => $value) {

	                $id = $key;
	                $file = $value['file'];
	                $dependencies = isset($value['dependencies']) ? $value['dependencies'] : array();

	                wp_deregister_script( $key );
	                wp_register_script( $key, plugins_url( $file , dirname(__FILE__)) , $dependencies , null, false);
	                wp_enqueue_script( $key );
	                
	            }
	        }

	    }

	}

}

if (!function_exists('cmshowcase_get_thumbnail_sizes')) {

	function cmshowcase_get_thumbnail_sizes($cpt) {

		$thumbsizes = get_intermediate_image_sizes();
		return $thumbsizes;

	}
}

if (!function_exists('cmshowcase_get_featured_img')) {

	function cmshowcase_get_featured_img( $id, $size = 'thumbnail', $email = '', $use_default = true, $default = '', $dsize = array(), $gravatar = true, $aspectratio = false) {


		$img_array= array();

		//First option - featured Image
		if(has_post_thumbnail($id)) {

			$thumbnail_id = get_post_thumbnail_id( $id );
			$image = wp_get_attachment_image_src( $thumbnail_id, $size ); 
			$img_array['src'] = $image[0];
			$img_array['width'] = $image[1];
			$img_array['height'] = $image[2];
			$img_array['alt'] =  get_post_meta($thumbnail_id, '_wp_attachment_image_alt', true);

			//correct image size in case custom is being used
			if(isset($dsize[0]) && $dsize[0] !=0 && $image[2] != 0 && $image[1] != 0) {
			$img_array['width'] = $dsize[0];
			$img_array['height'] = $dsize[0] * $image[2] / $image[1];
			}


		}

		//End Get featured Image
		
		//Get alternative methods - avatar or default image
		else {

			//if there's no email, show default
			if($email=='') {

				if($use_default) {
					$img_array['src'] = $default;
					$img_array['alt'] = __('Default Avatar','ttshowcase').$dsize[0];
					$img_array['width'] = $dsize[0];
					$img_array['height'] = $dsize[1];

					//correct proportional image
					if($aspectratio) {
					list($width, $height) = getimagesize($img_array['src']);
					$img_array['height'] = $dsize[0] * $height / $width;
					} else {

						$img_array['height'] = '';

					}
				} 

				else {
					$img_array['src'] = '';
					$img_array['alt'] = __('No Avatar','ttshowcase');
				}

			}

			//if there's an email, we check for avatar
			if($email!='') {

				if($gravatar) {

					$gdefault = false;
					if($use_default) {
						$gdefault = $default;
					} 

					$get_avatar = get_avatar( $email, $dsize[0], $gdefault );
					preg_match('#src=["|\'](.+)["|\']#Uuis', $get_avatar, $matches);

					//if there is an image
					if(isset($matches[1])) {
						$img_array['src'] = $matches[1];
						$img_array['alt'] = __('Avatar','ttshowcase');
						$img_array['width'] = $dsize[0];
						$img_array['height'] = ''; //$dsize[1];
						
						//correct image size
						//list($width, $height) = getimagesize($img_array['src']);
						//$img_array['height'] = $dsize[0] * $height / $width;

					} 

				}

				
				//if there's no avatar we set to default
				else {

					if($use_default) {
						$img_array['src'] = $default;
						$img_array['alt'] = __('Default Avatar','ttshowcase');

						$img_array['width'] = $dsize[0];
						$img_array['height'] = $dsize[1];

						//correct proportional image
						if($aspectratio) {
							list($width, $height) = getimagesize($img_array['src']);
							$img_array['height'] = $dsize[0] * $height / $width;
						} else {

						$img_array['height'] = '';

						}
						
					} 

					else {
						$img_array['src'] = '';
						$img_array['width'] = $dsize[0];
						$img_array['height'] = ''; //$dsize[1];
					}
				}
			} 
		}

		/*
		//now we correct the size
		//If the size is sent as an array - image size override
		if(is_array($size)) {


			$img_array['width'] = $size[0];

			if($width!=0) {
				$img_array['height'] = $size[0] * $height  / $width;
			}
			
		} 

		//if not, check for thumbnail sizes
		else {

			$thumbs = get_intermediate_image_sizes();

			foreach ($thumbs as $thumb) {

				if($size == $thumb) {

					if( in_array( $thumb, array( 'thumbnail', 'medium', 'large' ) ) ){

		 				$img_array['width'] = get_option( $thumb . '_size_w' );
		 				$img_array['height'] = get_option( $thumb . '_size_w' ) * $height  / $width;
		 			} 

		 			//last case, default size
		 			else {

		 				if( is_array($dsize) ) {
			 				
			 				$img_array['width'] = $dsize[0];
		 					$img_array['height'] = $dsize[1];
	 							
		 				}
		 			}
		 		}
			}
		}*/
		
		
		return $img_array;
	}

}

if(!function_exists('cmshowcase_gravatar_exists')) {

	function cmshowcase_gravatar_exists($email,$width) {

		$hashkey = md5(strtolower(trim($email)));
		$uri = 'http://www.gravatar.com/avatar/' . $hashkey . '?s='.$width.'&d=404';
		
		$handle = curl_init($uri);
		curl_setopt($handle,  CURLOPT_RETURNTRANSFER, TRUE);

		/* Get the HTML or whatever is linked in $url. */
		$response = curl_exec($handle);

		/* Check for 404 (file not found). */
		$httpCode = curl_getinfo($handle, CURLINFO_HTTP_CODE);
		if($httpCode == 404) {
		    $uri = false;
		}

		curl_close($handle);

		return $uri;

	}


}


if (!function_exists('cmshowcase_translate_array')) {

	function cmshowcase_translate_array($array,$domain) {


		if(is_array($array)) {
			foreach ($array as $key => $value) {
				$array[$key] = __($value,$domain);
			}
		}

		return $array;

	}

}

if (!function_exists('cmshowcase_get_url_target')) {

	function cmshowcase_get_url_target($target) {
		
		if($target=='_blank_no_follow') {
			return 'target="_blank" rel="nofollow"';
		}

		if($target=='_top') {
			return 'target="_top"';
		}

		if($target=='_blank') {
			return 'target="_blank"';
		}

		
	}

}

if (!function_exists('cmshowcase_get_saved_shortcodes')) {

	function cmshowcase_get_saved_shortcodes($showcase,$generator) {

		$options = get_option($showcase.'_saved_shortcodes',array());

		if(isset($options[$generator])) {
			return $options[$generator];
		}

	}

}


if (!function_exists('cmshowcase_build_pager')) {

	function cmshowcase_build_pager($cpt,$query,$labels = array(), $type = 'on') {

		$max_page = $query->max_num_pages;

		$html = '';

		if($max_page>1) {

			$numbers = "";

			$previous_page = "Previous Page";
			$next_page = "Next Page";

			if(!empty($labels)) {
				$previous_page = isset($labels['previous']) ? $labels['previous'] : $previous_page;
				$next_page = isset($labels['next']) ? $labels['next'] : $next_page;
			}

			$previous_page = __($previous_page,$cpt);
			$next_page = __($next_page,$cpt);

			//we build a unique identifier
			$queryval = substr($cpt,0,2).'page';

			$ii = 1;
			$hide = true;

			while ($ii <= $max_page) {

				$current = '';
				$curr_val = 0;

				if( isset($_GET[$queryval]) ) {
					
					$curr_val = intval($_GET[$queryval]);

				} else {

					$curr_val = 1;
					

				}

				if($curr_val == $ii) {
					$current = $cpt.'_current_page';
				}

				
				if($type=='short') {

					$range_max = $curr_val+1;
					$range_min = $curr_val-1;

					if( (($ii <= $range_max) && ($ii >= $range_min)) || ( $ii==1 || $ii == $max_page) ) {

						$hide = true;
						$numbers .= " <a class='".$cpt."_page ".$current."' href='?".$queryval."=".$ii."#".$cpt."'>".$ii."</a> ";
					
					} else {

						if($hide==true) {
							$hide = false;
							$numbers .= "...";
						}
						
					}

				} else {

					$numbers .= " <a class='".$cpt."_page ".$current."' href='?".$queryval."=".$ii."#".$cpt."'>".$ii."</a> ";

				}					

				$ii++;
			}


			$html .= "<div class='".$cpt."_pager'>";

			if(isset($_GET[$queryval]) && $_GET[$queryval]!='1' && $_GET[$queryval] < $max_page){ 
				
				$next = intval($_GET[$queryval]) + 1;
				$previous = intval($_GET[$queryval])-1;

				$html .= "<a class='".$cpt."_previous' href='?".$queryval."=".$previous."#".$cpt."'>".$previous_page."</a>";
				$html .= $numbers;
				$html .= "<a class='".$cpt."_next' href='?".$queryval."=".$next."#".$cpt."'>".$next_page."</a>";

			} if(!isset($_GET[$queryval]) || $_GET[$queryval]=='1' ) {

				$html .= $numbers." <a href='?".$queryval."=2#".$cpt."' class='".$cpt."_next'>".$next_page."</a>";
			
			}

			if(isset($_GET[$queryval]) && $_GET[$queryval]!='1' && $_GET[$queryval]>=$max_page){ 
				
				
				$previous = intval($_GET[$queryval])-1;

				$html .= "<a class='".$cpt."_previous' href='?".$queryval."=".$previous."#".$cpt."'>".$previous_page."</a>";
				$html .= $numbers;
				

			} 

			$html .= "</div>";

		}
		
		return $html;
		
	}
}


?>