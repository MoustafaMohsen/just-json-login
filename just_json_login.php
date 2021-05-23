<?php
/**
 * Plugin Name: Just JSON login
 * Description: Authentication for JSON API that's simple, use header "A-Authentication: Basic base64(username:password)"
 * Author URI: https://github.com/MoustafaMohsen
 * Version: 0.1
 * Plugin URI: https://github.com/MoustafaMohsen/
 */

function json_basic_auth_handler( $user ) {
    
    global $wp_json_basic_auth_error;
    
	$wp_json_basic_auth_error = null;
    
	// Don't authenticate twice
	if ( ! empty( $user ) ) {
        return $user;
	}

	// Check that we're trying to authenticate
	if ( isset( $_SERVER['PHP_AUTH_USER'] ) ) {
        $username = $_SERVER['PHP_AUTH_USER'];
        $password = $_SERVER['PHP_AUTH_PW'];
	}else{
		$http = 'A_Authorization';
		$http = strtoupper($http);
		$header = $_SERVER['HTTP_'.$http] ?? $_SERVER[$http] ?? NULL;
		preg_match('/Basic (.+)/', $header, $matchArr);
		$decoded = base64_decode($matchArr[1]);
		preg_match('/(.*):(.*)/', $decoded, $autArr);
		$username = $autArr[1];
		$password = $autArr[2];
	
	
		if(is_null($header)){
			
			return null;
		}
	
	}
	remove_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	$user = wp_authenticate( $username, $password );

	add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

	if ( is_wp_error( $user ) ) {
		$wp_json_basic_auth_error = $user;
		return null;
	}

	$wp_json_basic_auth_error = true;
	return $user->ID;


}
add_filter( 'determine_current_user', 'json_basic_auth_handler', 20 );

function json_basic_auth_error( $error ) {
	// Passthrough other errors
	if ( ! empty( $error ) ) {
		return $error;
	}

	global $wp_json_basic_auth_error;

	return $wp_json_basic_auth_error;
}
add_filter( 'rest_authentication_errors', 'json_basic_auth_error' );
