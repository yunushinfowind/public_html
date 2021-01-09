<?php
/*
Simple class to build layout constructors
*/


if ( !class_exists('cmshowcase_layouts') ) {

	class cmshowcase_layouts {

		public $cmshowcase_id;		//string
		public $layouts = array();	//array

		function __construct( $id , $layouts = array() ) {

				$this->cmshowcase_id = $id;

				foreach ($layouts as $layoutk => $layoutv) {
					require_once (dirname(__FILE__).'/../layouts/'.$layoutk.'/layout.php');
					$constructor = $layoutv['class'];
					$this->layouts[$id][$layoutk] = new $constructor($this->cmshowcase_id);
					unset($constructor);
				} 

				
		}
	}

}
			
			
			
			

?>