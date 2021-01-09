<?php
/**
 * Widget for Testimonials 
 */
class ttshowcase_Widget extends WP_Widget

{
	public

	function __construct()
	{
		
		$widget_ops = array(
			'classname' => 'ttshowcase_widget',
			'description' => __('Display saved Testimonials Layout','ttshowcase')
		);
		parent::__construct( 'ttshowcase_widget', __('Testimonials','ttshowcase'), $widget_ops);
	}

	public

	function widget($args, $instance)
	{
		extract($args);
		$title = apply_filters( 'widget_title', empty($instance['title']) ? '' : $instance['title'], $instance, $this->id_base);
		
		$shortcode = isset($instance['shortcode']) ? $instance['shortcode'] : '[show-testimonials]';
		
		$return = '';

		$return .= $before_widget;

		if (!empty($title)) $return .= $before_title . $title . $after_title;

		if($shortcode != '') {
			$saved_shortcodes = get_option('ttshowcase_saved_shortcodes',array());  
			foreach ($saved_shortcodes as $sh) {
	        
	          foreach ($sh as $key => $value) {
	            if($key == $shortcode) {
	            	$return .= do_shortcode($value);
	            }
	            

	          }
	        
	        }

			
		}
		
		$return .= $after_widget;

		echo $return;

	}

	public

	function update($new_instance, $old_instance)
	{
		$instance = $old_instance;
		$instance['title'] = strip_tags($new_instance['title']);
		$instance['shortcode'] = $new_instance['shortcode'];
		return $instance;
	}

	public

	function form($instance)
	{
		$instance = wp_parse_args((array)$instance, array(
			'title' => '',
			'shortcode' => ''
		));
		$title = strip_tags($instance['title']);
		$shortcode = isset($instance['shortcode']) ? $instance['shortcode'] : '';

		echo '<p><label for="'.$this->get_field_id( 'title' ).'">Title:</label>
        	  <input class="widefat" id="'.$this->get_field_id( 'title' ).'" name="'.$this->get_field_name( 'title' ).'" type="text" value="'.esc_attr($title).'">
        	  </p>';

        $saved_shortcodes = get_option('ttshowcase_saved_shortcodes',array());  
  

      	if(count($saved_shortcodes)>0) {


			echo '
			<p>
	        <label for="'.$this->get_field_id( 'shortcode' ).'">'.__('Layout to display:','ttshowcase').'</label>
	     
	        <select id="'.$this->get_field_id( 'shortcode' ).'" name="'.$this->get_field_name( 'shortcode' ).'">';

	        echo "<option value='' ".selected($shortcode, '' )."> -- Select -- </option>";	
	        
	        foreach ($saved_shortcodes as $sh) {
	        
	          foreach ($sh as $key => $value) {
	            $options[$key] = $key;

	            echo "<option value='".$key."' ".selected($shortcode, $key )."> ".$key."</option>";

	          }
	        
	        }

	        echo '</select>';

	        echo "<p class='howto'>".__('You can select the shortcode layouts previously saved using the Shortcode Generator.','ttshowcase')."</p>";

      	} 
		
		else {

			echo "<p>".__('Please create a layout shortcode first','ttshowcase')."</p>";

		}

	}
}

add_action( 'widgets_init', 'register_ttshowcase_widget' );
/**
 * Register widget
 *
 * This functions is attached to the 'widgets_init' action hook.
 */

function register_ttshowcase_widget()
{
	register_widget( 'ttshowcase_Widget' );
}

?>
