<?php

namespace Takuya\LEClientDNS01\DnsResolver;

use Takuya\LEClientDNS01\DnsResolver\Binary\BinDecode;
use Takuya\LEClientDNS01\DnsResolver\Binary\BinEncode;

class DnsResolverBinStr extends DnsResolver {
  
  protected static function query( $name, $type, $ns_server, $timeout ) {
    $timeout = 1;
    $binary_packet = static::build_query( $name, $type );
    $q = [
      'id'     => static::decodeQueryId( $binary_packet ),
      'name'   => $name,
      'type'   => static::getQueryType( static::getTypeInt( $type ) ),
      'server' => $ns_server,
    ];
    $start = microtime( true );
    $response = static::send_query( $binary_packet, $ns_server, $timeout );
    $elapsed = microtime( true ) - $start;
    if( $response === false ) throw new \RuntimeException( 'Dns Connection failed.' );
    if( $q['id'] != static::decodeQueryId( $response ) ) throw new \RuntimeException( 'packet id modified' );
    $ret = static::parse_response( $response );
    return array_merge( ['QUERY' => [$q], 'TIME' => $elapsed], $ret );
  }
  
  protected static function read_response_record( string $res_packet_bin, int $cnt, int $start_pos, int $sect = 0 ) {
    $rr = [];
    for ( $i = 0; $i < $cnt; $i++ ) {
      [$next, $ret] = static::parseResponseRecord( $res_packet_bin, $start_pos, $sect );
      $rr[] = $ret;
      // modify pos to read next.
      $start_pos = $next;
    }
    return [$rr, $start_pos];
  }
  
  protected static function parse_response( string $response_bin ) {
    // header
    /**
     * typedef struct __attribute__((packed))   {
     * uint16_t id;
     * uint16_t flags;
     * uint16_t qdcount;
     * uint16_t ancount;
     * uint16_t nscount;
     * uint16_t arcount;
     * } dns_header_t;
     */
    $obj = new \stdClass();
    $obj->queryid = BinDecode::read_uint16( $response_bin, $offset = 0 );
    $obj->q_flags = BinDecode::read_uint16( $response_bin, $offset += 2 );
    $obj->qdcount = BinDecode::read_uint16( $response_bin, $offset += 2 );
    $obj->ancount = BinDecode::read_uint16( $response_bin, $offset += 2 );
    $obj->nscount = BinDecode::read_uint16( $response_bin, $offset += 2 );
    $obj->arcount = BinDecode::read_uint16( $response_bin, $offset += 2 );
    $offset += 2;
    // skip qdata
    $qname_end_pos = strpos( BinDecode::read_string( $response_bin, $offset ), "\x00" ) + $offset;
    // ANSWER SECTION
    $ans_start_pos = $qname_end_pos + 1 + 2 + 2; // qname(variable), 0x00 (1) , TYPE(2),IN(2)
    [$ans, $offset] = static::read_response_record( $response_bin, $obj->ancount, $ans_start_pos, 0 );
    // Authority Section
    $auth_start_pos = $offset;
    [$auths, $offset] = static::read_response_record( $response_bin, $obj->nscount, $auth_start_pos, 1 );
    // Additional Section.
    $adds_start_pos = $offset;
    [$adds, $offset] = static::read_response_record( $response_bin, $obj->arcount, $adds_start_pos, 2 );
    if( $offset != strlen( $response_bin ) ) throw new \RuntimeException( 'read packet failed.' );
    return ['ANSWER' => $ans, 'AUTHORITY' => $auths, 'ADDITIONAL' => $adds, 'PACKET_SIZE' => strlen( $response_bin )];
  }
  
  protected static function build_query( $name, $type ) {
    // 1. バッファ確保
    $buffer = BinEncode::buffer( 32 );
    // 2. ヘッダー設定
    /**
     * typedef struct __attribute__((packed))   {
     * uint16_t id;
     * uint16_t flags;
     * uint16_t qdcount;
     * uint16_t ancount;
     * uint16_t nscount;
     * uint16_t arcount;
     * } dns_header_t;
     */
    BinEncode::write_uint16( $buffer, 0, rand( 10000, 65535 ) );      // id
    BinEncode::write_uint16( $buffer, 2, 0x0100 );                    // flags RD=1
    BinEncode::write_uint16( $buffer, 4, 0x01 );                      // qdcount
    BinEncode::write_uint16( $buffer, 6, 0x00 );                      // nscount
    BinEncode::write_uint16( $buffer, 8, 0x00 );                      // arcount
    BinEncode::write_uint16( $buffer, 10, static::$EDNS_ENABLED );    // arcount
    //
    // 4. QUESTION SECTION.
    //   4.1 name label 圧縮
    $offset = 12;
    foreach ( array_filter( explode( '.', rtrim( trim( $name ), '.' ) ) ) as $label ) {
      if( !empty( $label ) ) {
        BinEncode::write_uint8( $buffer, $offset, strlen( $label ) );
        BinEncode::write_chars( $buffer, $offset += 1, $label );
        $offset += strlen( $label );
      }
    }
    BinEncode::write_uint8( $buffer, $offset, 0x00 );// End of question.
    //
    //   4.2 type class
    //
    BinEncode::write_uint16( $buffer, $offset += 1, self::getTypeInt( $type ) );
    BinEncode::write_uint16( $buffer, $offset += 2, 0x01 );
    // 05. EDNS0
    if( static::$EDNS_ENABLED ) {
      /**
       * typedef struct __attribute__((packed)) {
       * uint8_t  name;
       * uint16_t type;
       * uint16_t udp_size;
       * uint32_t ttl;
       * uint16_t rdlength;
       * } dns_opt_rr_t;
       */
      BinEncode::write_uint8( $buffer, $offset += 2, 0x00 );  // name
      BinEncode::write_uint16( $buffer, $offset += 1, 41 );   // type
      BinEncode::write_uint16( $buffer, $offset += 2, 1232 ); // udp_size
      BinEncode::write_uint32( $buffer, $offset += 2, 0 );    // ttl
      BinEncode::write_uint16( $buffer, $offset += 4, 0 );    // rdlength
    }
    //dump( self::hex_dump( $buffer ) );
    return $buffer;
  }
}