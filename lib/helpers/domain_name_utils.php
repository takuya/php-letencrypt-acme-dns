<?php
namespace Takuya\Utils;

if ( !function_exists( __NAMESPACE__.'\assert_str_is_domain' ) ) {
  function assert_str_is_domain ( string $name ): bool {
    $result = filter_var( $name, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME | FILTER_NULL_ON_FAILURE );
    return (bool)$result;
  }
}
if ( !function_exists( __NAMESPACE__.'\assert_ipv4_address' ) ) {
  function assert_ipv4_address ( string $ns_server ): bool {
    $result = filter_var( $ns_server, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_NULL_ON_FAILURE );
    return (bool)$result;
  }
}


if ( !function_exists( __NAMESPACE__.'\base_domain' ) ) {
  function base_domain ( $domain_name ): string {
    $chunk = explode( '.', $domain_name );
    if ( sizeof( $chunk ) > 2 ) {
      return implode( '.', array_slice( $chunk, -2, 2 ) );
    } else {
      return $domain_name;
    }
  }
}
if ( !function_exists( __NAMESPACE__.'\sub_domain' ) ) {
  function sub_domain ( $domain_name ): string {
    $base_domain = base_domain( $domain_name );
    $sub_domain = str_replace( ".{$base_domain}", '', $domain_name );
    return $sub_domain;
  }
}
if ( !function_exists( __NAMESPACE__.'\domain_ns' ) ) {
  function domain_ns ( string $domain_name ): string {
    if ( str_starts_with( $domain_name, '.' ) ) {
      $domain_name = preg_replace( '|^\.|', '', $domain_name );
    }
    if ( !str_ends_with( $domain_name, '.' ) ) {
      $domain_name = $domain_name.'.';
    }
    $result = [];
    $name = $domain_name;
    while ( empty( $result = $result = dns_get_record( $name, DNS_NS ) ) ) {
      // Generic router DNS Resolver(ex.dnsmasq) may not return SOA and Additional.
      // Instead, Parent domain DNS_NS query.
      $name = parent_domain( $name, true );
      if ( empty( $name ) ) {
        throw new \RuntimeException();
      }
    }
    $result = array_map( fn( $e ) => $e['target'], $result );
    return $result[rand( 0, sizeof( $result ) - 1 )];
  }
}
if ( !function_exists( __NAMESPACE__.'\parent_domain' ) ) {
  function parent_domain ( $domain_name, $stop_at_tld = true ): string {
    $chunk = explode( '.', $domain_name );
    $parent_domain = implode( '.', array_slice( $chunk, 1 ) );
    $base_domain = base_domain( $domain_name );
    if ( sizeof( $chunk ) > 1 && $stop_at_tld ) {
      return strlen( $parent_domain ) >= strlen( $base_domain ) ? $parent_domain : $base_domain;
    } else {
      return sizeof( $chunk ) == 2 ? array_pop( $chunk ) : ( sizeof( $chunk ) == 1 ? '.' : '' );
    }
  }
}




