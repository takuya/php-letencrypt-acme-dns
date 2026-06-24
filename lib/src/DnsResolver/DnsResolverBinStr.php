<?php

namespace Takuya\LEClientDNS01\DnsResolver;

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
    if( $q['id'] != static::decodeQueryId( $response ) ) throw new \RuntimeException( 'packet id modified' );
    $ret = static::parse_response( $response );
    return array_merge( ['QUERY' => [$q], 'TIME' => $elapsed], $ret );
  }
  
  protected static function read_response_record( string $res_packet_bin, int $cnt, int $start_pos ) {
    $rr = [];
    for ( $i = 0; $i < $cnt; $i++ ) {
      $ret = static::parseResponseRecord( $res_packet_bin, $start_pos );
      $start_pos += 12 + $ret['rdlength'];
      if( $ret['type'] == static::getTypeInt( 'OPT' ) ) {
        // TODO:: calc rr size.
        $start_pos--;
      }
      
      $rr[] = $ret;
    }
    return [$rr, $start_pos];
  }
  
  protected static function parse_response( string $resposse_bin ) {
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
    $obj->queryid = BinDecode::read_uint16( $resposse_bin, $offset = 0 );
    $obj->q_flags = BinDecode::read_uint16( $resposse_bin, $offset += 2 );
    $obj->qdcount = BinDecode::read_uint16( $resposse_bin, $offset += 2 );
    $obj->ancount = BinDecode::read_uint16( $resposse_bin, $offset += 2 );
    $obj->nscount = BinDecode::read_uint16( $resposse_bin, $offset += 2 );
    $obj->arcount = BinDecode::read_uint16( $resposse_bin, $offset += 2 );
    $offset += 2;
    // skip qdata
    $qname_end_pos = strpos( BinDecode::read_string( $resposse_bin, $offset ), "\x00" ) + $offset;
    // ANSWER SECTION
    $ans_start_pos = $qname_end_pos + 2 + 2 + 1;
    [$ans, $offset] = static::read_response_record( $resposse_bin, $obj->ancount, $ans_start_pos );
    // Authority Section
    $auth_start_pos = $offset;
    [$auths, $offset] = static::read_response_record( $resposse_bin, $obj->nscount, $auth_start_pos );
    // Additional Section.
    $adds_start_pos = $offset;
    [$adds, $offset] = static::read_response_record( $resposse_bin, $obj->arcount, $adds_start_pos );
    //
    if( $offset != strlen( $resposse_bin ) ) throw new \RuntimeException( 'read packet failed.' );
    return ['ANSWER' => $ans, 'AUTHORITY' => $auths, 'ADDITIONAL' => $adds, 'PACKET_SIZE' => strlen( $resposse_bin )];
  }
  
  protected static function build_query( $name, $type ) {
    // 1. バッファ確保
    $buffer = BinEncode::buffer( 150 );
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
    foreach ( explode( '.', $name ) as $label ) {
      BinEncode::write_uint8( $buffer, $offset, strlen( $label ) );
      BinEncode::write_chars( $buffer, $offset += 1, $label );
      $offset += strlen( $label );
    }
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
    //dd( self::hex_dump( $buffer ) );
    return $buffer;
  }
}