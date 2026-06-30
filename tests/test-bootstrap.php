<?php

// tests/bootstrap.php
if( in_array(basename($_SERVER['PHP_SELF']),[basename(__FILE__),'phpunit']) ) {
  $autoload = function() {
    $autoload = realpath( dirname( __DIR__ ).'/vendor/autoload.php' );
    if( empty( $autoload ) ) {
      return;
    }
    require_once $autoload;
  };
  $load_env = function() {
    $f_name = realpath( __DIR__.'/../secret-variables.sh' );
    if( empty( $f_name ) ) {
      return;
    }
    if (!empty(getenv('LE_CLOUDFLARE_TOKEN'))) {
      return;
    }
    // parse file
    $f = new SplFileObject( $f_name );
    $ret = array_filter( iterator_to_array( $f ), fn( $e ) => preg_match( '/export .+=.+/', $e ) );
    $ret = array_map( 'trim', $ret );
    $ret = array_map( function( $e ) {
      preg_match( '/export (.+)=(.+)$/', $e, $match );
      return array_slice( $match, 1 );
    }, $ret );
    $ret = array_values( $ret );
    $ret = array_map( fn( $e ) => "{$e[0]}=$e[1]", $ret );
    // load
    array_map( fn( $e ) => putenv( $e ), $ret );
  };
  //
  $autoload();
  $load_env();
  unset( $autoload );
  unset( $load_env );
}

