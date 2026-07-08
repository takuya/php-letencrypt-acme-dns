<?php

namespace Takuya\Utils;

use Takuya\LEClientDNS01\DnsResolver\DnsResolver;
use Takuya\LEClientDNS01\DnsCheck\ResolveConf;

if( !function_exists( __NAMESPACE__.'\dns_resolve' ) ) {
  ///**
  // * Resolve dns From SOA.
  // * @note Not all router resolver answers SOA. using NS instead.
  // * @param string $name
  // * @param string $type
  // * @return string
  // * @throws Net_DNS2_Exception
  // */
  //function dns_resolve( string $name, string $type, $ns_server = null, $timeout = 5 ): string {
  //  $type = strtoupper( $type );
  //  $ns_server = $ns_server ?? domain_ns( $name );
  //  $ns_server_ips = assert_ipv4_address( $ns_server ) ? [$ns_server]
  //    : array_map( fn( $e ) => $e['ip'], dns_get_record( $ns_server, DNS_A ) );
  //  try {
  //    $resolver = new Net_DNS2_Resolver( ['nameservers' => $ns_server_ips, 'timeout' => $timeout] );
  //    $result = $resolver->query( $name, $type );
  //    $content = match ( $type ) {
  //      "A" => array_map( fn( $e ) => $e->address, array_filter( $result->answer, fn( $e ) => $e->type == "A" ) ),
  //      "NS" => array_map( fn( $e ) => $e->nsdname, $result->answer ),
  //      "SOA" => array_map( fn( $e ) => $e->mname, $result->answer ),
  //      "TXT" => array_map( fn( $e ) => join( PHP_EOL, $e?->text ), array_filter( $result->answer,
  //        fn( $e ) => strcasecmp( $name, $e->name ) === 0 && get_class( $e ) == "Net_DNS2_RR_TXT" ) ),
  //      "MX" => ( function( $answer ) {
  //        usort( $answer, function( $a, $b ) { return $a->preference <=> $b->preference; } );
  //        return array_reduce( $answer, function( $mx, $e ) {
  //          $mx[$e->preference] = $e->exchange;
  //          return $mx;
  //        }, [] );
  //      } )( $result->answer )
  //    };
  //    return implode( PHP_EOL, $content );
  //  } catch (Net_DNS2_Exception $e) {
  //    if( Net_DNS2_Lookups::RCODE_NXDOMAIN == $e->getCode() ) {
  //      return '';
  //    }
  //    if( Net_DNS2_Lookups::E_NS_SOCKET_FAILED == $e->getCode() ) {
  //      // file_put_contents( 'php://stderr','Network Error. Check outbound udp/53 opened.'.PHP_EOL );
  //      throw $e;
  //    }
  //    throw $e;
  //  }
  //}
  /**
   * Resolve dns From SOA.
   * @note Not all router resolver answers SOA. using NS instead.
   * @param string $name
   * @param string $type
   * @return string rr_data: one of dns response record data, if failed empty string '' .
   * @throws \RuntimeException
   * @author takuya
   * @since  2026-06-30
   * @note  remove pear net_dns , Use my dns resolver.
   */
  function dns_resolve( string $name, string $type, $ns_server = null, $timeout = 5 ): string {
    // TODO ローカルサーバーに対応する
    $type = strtoupper($type);
    // 常に、ns レコードへ問い合わせる
    $ns_server = $ns_server ?? domain_ns( $name );
    $ns_server_ips = assert_ipv4_address( $ns_server ) ? [$ns_server]
      : array_map( fn( $e ) => $e['ip'], dns_get_record( $ns_server, DNS_A ) );
    try {
      $resolver = DnsResolver::create();
      $ret = $resolver->resolve($name,$type,$ns_server_ips[0],$timeout);
      if ( empty($ret['ANSWER']) && $type!='SOA' ) throw new \RuntimeException('record is empty');
      return match($type){
        "SOA"=> $ret['ANSWER'][0]['rdata']['mname']??$ret['AUTHORITY'][0]['rdata']['mname'],
        "TXT"=> implode("\n",array_map(fn($e)=>$e['rdata'],$ret['ANSWER'])),
        default=>$ret['ANSWER'][0]['rdata']
      };
    }catch (\RuntimeException $e){
      return match( $e->getCode()){
        DnsResolver::DNS_CONNECTION_FAILED=>false,// be cast to ''
        default=> throw $e,
      };
    }
  }
}

if( !function_exists( __NAMESPACE__.'\is_directly_resolve_allowed' ) ) {
  /**
   * @param string $name    Internet Domain Name
   * @param int    $timeout seconds.
   * @return bool
   */
  function is_directly_resolve_allowed( $name, int $timeout = 1 ): bool {
    try {
      $ret= dns_resolve( $name, "A", null, $timeout );
      return  !empty($ret) ;
    } catch (\Exception $e) {
      return match ( $e->getCode() ) {
        DnsResolver::DNS_PACKECT_ID_NOT_MATCH => false,
        default => throw $e
      };
    }
  }
}
if( !function_exists( __NAMESPACE__.'\is_local_dns_available' ) ) {
  function is_local_dns_available(): bool {
    try {
      $server = resolve_conf()['nameserver'][0];
      $ret= dns_resolve( 'google.com', "A", $server, 1 );
      return  !empty($ret) ;
    } catch (\Exception $e) {
      return match ( $e->getCode() ) {
        DnsResolver::DNS_PACKECT_ID_NOT_MATCH => false,
        default => throw $e
      };
    }
  }
}

if (!function_exists( __NAMESPACE__.'\resolve_conf' )  ) {
  function resolve_conf(): array|bool {
    return ResolveConf::parse();
  }
}

