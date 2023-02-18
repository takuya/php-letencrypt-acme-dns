<?php

if ( !function_exists( 'assert_str_is_domain' ) ) {
  function assert_str_is_domain ( $name ): bool {
    $result = filter_var( $name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME | FILTER_NULL_ON_FAILURE );
    return (bool)$result;
  }
}


if ( !function_exists( 'base_domain' ) ) {
  function base_domain ( $domain_name ): string {
    $chunk = explode( '.', $domain_name );
    if ( sizeof( $chunk ) > 2 ) {
      return implode( '.', array_slice( $chunk, -2, 2 ) );
    } else {
      return $domain_name;
    }
  }
}
if ( !function_exists( 'sub_domain' ) ) {
  function sub_domain ( $domain_name ): string {
    $base_domain = base_domain( $domain_name );
    $sub_domain = str_replace( ".{$base_domain}", '', $domain_name );
    return $sub_domain;
  }
}
if ( !function_exists( 'domain_ns' ) ) {
  function domain_ns ( $domain_name ) {
    $chunk = explode( '.', $domain_name );
    while ( sizeof( $chunk ) > 1 ) {
      array_shift( $chunk );
      $parent = implode( '.', $chunk );
      $ret = dns_get_record( $parent, DNS_NS );
      if ( !empty( $ret ) ) {
        $ret = array_map( function( $e ) { return $e['target']; }, $ret );
        return $ret[0];
      } else {
        continue;
      }
    }
    return null;
  }
}
if ( !function_exists( 'parent_domain' ) ) {
  function parent_domain ( $domain_name ): string {
    $chunk = explode( '.', $domain_name );
    $parent_domain = implode( '.', array_slice( $chunk, 1 ) );
    $base_domain = base_domain( $domain_name );
    return strlen( $parent_domain ) >= strlen( $base_domain ) ? $parent_domain : $base_domain;
  }
}




