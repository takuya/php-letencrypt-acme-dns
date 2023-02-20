<?php

namespace Takuya\Utils;

use Net_DNS2_Resolver;
use Net_DNS2_Lookups;
use Net_DNS2_Exception;

if ( !function_exists( __NAMESPACE__.'\dns_resolve' ) ) {
  /**
   * Resolve dns From SOA.
   * @note Not all router resolver answers SOA. using NS instead.
   * @param string $name
   * @param string $type
   * @return string
   * @throws Net_DNS2_Exception
   */
  function dns_resolve ( string $name, string $type ): string {
    $type = strtoupper( $type );
    $ns_server = domain_ns( $name );
    $ns_server_ips = assert_ipv4_address( $ns_server ) ? [$ns_server]
      : array_map( fn( $e ) => $e['ip'], dns_get_record( $ns_server, DNS_A ) );
    
    try {
      $resolver = new Net_DNS2_Resolver( ['nameservers' => $ns_server_ips, 'timeout' => 5] );
      $result = $resolver->query( $name, $type );
      $content = match ( $type ) {
        "A" => array_map( fn( $e ) => $e->address, $result->answer ),
        "NS" => array_map( fn( $e ) => $e->nsdname, $result->answer ),
        "SOA" => array_map( fn( $e ) => $e->mname, $result->answer ),
        "TXT" => array_map( fn( $e ) => join( PHP_EOL, $e->text ), $result->answer ),
        "MX" => ( function( $answer ) {
          usort( $answer, function( $a, $b ) { return $a->preference > $b->preference; } );
          return array_reduce( $answer, function( $mx, $e ) {
            $mx[$e->preference] = $e->exchange;
            return $mx;
          }, [] );
        } )( $result->answer )
      };
      return implode( PHP_EOL, $content );
    } catch (Net_DNS2_Exception $e) {
      if ( Net_DNS2_Lookups::RCODE_NXDOMAIN == $e->getCode() ) {
        return '';
      }
      if ( Net_DNS2_Lookups::E_NS_SOCKET_FAILED == $e->getCode() ) {
        printf( 'Network Error. Check outbound udp/53 opened.' );
        throw $e;
      }
      throw $e;
    }
  }
}
