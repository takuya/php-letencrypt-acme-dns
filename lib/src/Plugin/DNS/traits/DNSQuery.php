<?php

namespace Takuya\LEClientDNS01\Plugin\DNS\traits;

trait DNSQuery {
  public function query ( $name, $type ): string {
    $type = strtoupper( $type );
    //
    try {
      // check ns.
      $ns = \domain_ns( $name );
      if ( filter_var( $ns, FILTER_VALIDATE_IP ) === false ) {
        $r = new \Net_DNS2_Resolver( ['timeout' => 3] );
        $result = $r->query( $ns );
        $authority_nameserver_ips = array_map( fn( $answer ) => $answer->address, $result->answer );
        $ns = $authority_nameserver_ips[0];
      }
      // check record
      $r = new \Net_DNS2_Resolver( ['nameservers' => [$ns], 'timeout' => 5] );
      $result = $r->query( $name, $type );
      $content = implode( PHP_EOL, array_map( fn( $e ) => implode( PHP_EOL, $e->text ), $result->answer ) );
      return $content;
    } catch (\Net_DNS2_Exception $e) {
      if ( \Net_DNS2_Lookups::RCODE_NXDOMAIN == $e->getCode() ) {
        return '';
      }
      throw $e;
    }
  }
  
}