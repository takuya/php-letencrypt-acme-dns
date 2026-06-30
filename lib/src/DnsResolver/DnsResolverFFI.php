<?php

namespace Takuya\LEClientDNS01\DnsResolver;

use \FFI;

class DnsResolverFFI extends DnsResolver {
  
  protected static function dns_ffi_def() {
    $cdef = "
      // エンディアン解決
      uint16_t htons(uint16_t hostshort);
      uint32_t ntohl(uint32_t netlong);
      // DNS パケット
      typedef struct __attribute__((packed))   {
          uint16_t id;
          uint16_t flags;
          uint16_t qdcount;
          uint16_t ancount;
          uint16_t nscount;
          uint16_t arcount;
          uint8_t data[500];
      } dns_packet_t;
      // DNS ヘッダ
      typedef struct __attribute__((packed))   {
          uint16_t id;
          uint16_t flags;
          uint16_t qdcount;
          uint16_t ancount;
          uint16_t nscount;
          uint16_t arcount;
      } dns_header_t;
      // レスポンス・レコード・データ・ヘッダ
      typedef struct  __attribute__((packed)) {
        uint16_t name;
        uint16_t type;
        uint16_t class;
        uint32_t ttl;
        uint16_t rdlength;
      } dns_rr_header_t;
      // OPT・レコード・データ EDNS0 用
      typedef struct __attribute__((packed)) {
        uint8_t  name;
        uint16_t type;
        uint16_t udp_size;
        uint32_t ttl;
        uint16_t rdlength;
      } dns_opt_rr_t;
    ";
    $ffi = FFI::cdef( $cdef, "libc.so.6" );
    
    return $ffi;
  }
  
  protected static function ffi_query( string $name, string $type, string $ns_server, int $timeout = 5 ) {
    $ffi = static::dns_ffi_def();
    [$ffi, $binary_packet] = static::build_query( $ffi, $name, $type );
    $q = [
      'id'     => static::decodeQueryId( $binary_packet ),
      'name'   => $name,
      'type'   => static::getQueryType( static::getTypeInt( $type ) ),
      'server' => $ns_server,
    ];
    //
    $start = microtime( true );
    $response = static::send_query( $binary_packet, $ns_server, $timeout );
    $elapsed = microtime( true ) - $start;
    if( $q['id'] != static::decodeQueryId( $response ) ) throw new \RuntimeException( 'packet id modfied' );
    //
    $ret = static::parse_response( $ffi, $response );
    return ['QUERY' => [$q], 'ANSWER' => $ret, 'TIME' => $elapsed];
  }
  
  
  protected static function parse_response( $ffi, $response ) {
    $res_chars_ffi = $ffi->new( "char[".( strlen( $response ) + 1 )."]" );
    FFI::memcpy( $res_chars_ffi, $response, strlen( $response ) );
    
    $res_header_ffi = $ffi->new( "dns_header_t" );
    FFI::memcpy( FFI::addr( $res_header_ffi ), $res_chars_ffi, FFI::sizeof( $ffi->type( 'dns_header_t' ) ) );
    $ancount = $ffi->htons( $res_header_ffi->ancount );
    
    //
    for (
      $ptr = $ffi->cast( 'char *', $res_chars_ffi ), $i = FFI::sizeof( $ffi->type( "dns_header_t" ) );
      $i < strlen( $response );
      $i++
    ) {
      if( FFI::string( $ptr[$i], 1 ) == "\x00" ) {
        $qname_end_pos = $i;
        break;
      }
    }
    $ans_start_pos = $qname_end_pos + 1 + 2 + 2;
    $packet_addr = $ffi->cast( 'uint8_t *', FFI::addr( $res_chars_ffi[0] ) );
    $answer_pos = [];
    for ( $offset = $ans_start_pos, $i = 0; $i < $ancount; $i++ ) {
      $answer_pos[] = $offset;
      $a = $ffi->cast( "dns_rr_header_t *", FFI::addr( $packet_addr[$offset] ) );
      
      $rdlength = $ffi->htons( $a->rdlength );
      $offset += 12 + $rdlength;
    }
    
    $ans = [];
    foreach ( $answer_pos as $pos ) {
      $ans[] = static::parseResponseRecord( $response, $pos );
    }
    // TODO parse Additional sections.
    //dd(
    //  $ffi->htons($res_header_ffi->ancount),
    //  $ffi->htons($res_header_ffi->nscount),
    //  $ffi->htons($res_header_ffi->arcount),
    //);
    
    return $ans;
  }
  
  
  protected static function build_query( $ffi, string $name, string $type ) {
    // 1. バッファ確保
    $max_len = 512;
    $buffer = $ffi->new( "uint8_t[$max_len]" );
    $packet = $ffi->cast( "dns_packet_t", $buffer );
    // 2. ヘッダー設定 (htonsでネットワークバイトオーダーに変換)
    $packet->id = $ffi->htons( rand( 10000, 65535 ) );
    $packet->flags = $ffi->htons( 0x0100 ); // RD=1
    $packet->qdcount = $ffi->htons( 1 );
    $packet->ancount = 0;
    $packet->nscount = 0;
    $packet->arcount = $ffi->htons( static::$E_DNS['enabled'] );
    //dump($id);
    
    // 3. Questionセクション構築
    $ptr = $ffi->cast( "uint8_t*", $packet->data );
    foreach ( explode( '.', $name ) as $label ) {
      $len = strlen( $label );
      
      $ptr[0] = $len;
      FFI::memcpy( FFI::addr( $ptr[1] ), $label, $len );
      // 長さ(1バイト) + 文字列分($len)
      /** @noinspection PhpArithmeticTypeCheckInspection */
      $ptr += ( $len + 1 );
    }
    $ptr[0] = 0;
    $ptr++;
    
    // 4. 型とクラスをセット
    $ptr[0] = 0;
    $ptr[1] = self::getTypeInt( $type );
    $ptr[2] = 0;
    $ptr[3] = 1;// IN class: 固定
    // EDNS0
    if( static::$E_DNS ) {
      $ptr += 4;
      $opt = $ffi->new( "dns_opt_rr_t" );
      $opt->name = 0;
      $opt->type = $ffi->htons( 41 );
      $opt->udp_size = $ffi->htons( 1232 );
      $opt->ttl = 0;
      $opt->rdlength = 0;
      FFI::memcpy(
        FFI::addr( $ptr[0] ),
        FFI::addr( $opt ),
        FFI::sizeof( $opt )
      );
    }
    
    
    //dd( self::hex_dump(FFI::string( $packet, FFI::sizeof( $packet ) )) );
    return [$ffi, FFI::string( $packet, FFI::sizeof( $packet ) )];
  }
  
  
  protected static function query( $name, $type, $ns_ip, $timeout ) {
    return static::ffi_query( $name, $type, $ns_ip, $timeout );
  }
}