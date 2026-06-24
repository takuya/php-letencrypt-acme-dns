<?php

namespace Takuya\LEClientDNS01\DnsResolver;

abstract class DnsResolver {
  /*
  
    DNS  Packet Header
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15| <- index表見出し: ビット目盛り (計16ビット=2バイト)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      ID                       | <- 乱数 :Transaction ID (2バイト)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   | <- クエリ種類：各種フラグ (計2バイト)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    QDCOUNT                    | <- クエリ数：質問数 (2バイト / 1以外は使わない。)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+       依頼の応答にExists と no Exists(NXDOMAIN)が交じると混乱する
    |                    ANCOUNT                    | <- 回答リソースレコード数 (2バイト)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    NSCOUNT                    | <- 権威サーバーリソースレコード数 (2バイト)　
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ARCOUNT                    | <- 追加情報リソースレコード数 (2バイト)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    
    |名称|type|	説明|
    |:---:|:---:|:---|
    |ID|random int(16)|	 DNSのトランザクションID。クエリ時に指定し、応答パケットはコピーを入れる。連番禁止|
    |QR|flag(1bit)|	0=>問い合わせが, 1=>応答|
    |OPCODE|4bit num |	問い合わせの種類を指定する。0=>通常のクエリ、4=>Notify、5=>Update|
    |AA|flag(1bit)|	管理権限がある応答であることを示す|
    |TC|flag(1bit)|	パケット長制限などで応答が切り詰められていることを示す|
    |RD|flag(1bit)|	名前解決を要求するビット。0=>権威DNSサーバへの問合せで、 1=>フルリゾルバへの問合せ|
    |RA|flag(1bit)|	名前解決可能であることを示す|
    |Z|flag(1bit)|	将来のために予約。常に0|
    |AD|flag(1bit)|	DNSSEC検証に成功したことを示す（応答）／ 応答のADビットを理解できることを示す（問い合わせ）,ほぼ常に0|
    |CD|flag(1bit)|	DNSSEC検証の禁止、ほぼ常に0|
    |QDCOUNT|quert count int(16)|	Questionセクション数,ほぼ常に 0x01 |
    |ANCOUNT|answer count |	Answerセクションのリソースレコード（RR）数|
    |NSCOUNT|int(16)|	AuthorityセクションのRR数|
    |ARCOUNT|int(16)|	AdditionalセクションのRR数|
  
  
   */
  static array $E_DNS = [
    'enabled'  => 1,
    'disabled' => 0,
  ];
  static int $EDNS_ENABLED = 1;
  static array $query_types = [
    1   => "A",            // IPv4
    2   => "NS",           // ネームサーバ
    5   => "CNAME",        // 別名
    6   => "SOA",          // Zone情報
    12  => "PTR",          // 逆引き
    15  => "MX",           // メールサーバ
    16  => "TXT",          // テキスト
    28  => "AAAA",         // IPv6
    33  => "SRV",          // サービス
    41  => "OPT",          // サービス
    257 => "CAA",          // 証明書発行制御
  ];
  static array $query_class = [
    1         => "IN", // インターネット。通常はこれ
    3         => "CHAOS",
    4         => "HS",
    'default' => null,
  ];
  
  public static function create( string $name = 'ffi' ): DnsResolver {
    if( $name == 'ffi' && extension_loaded( 'ffi' ) ) {
      return new DnsResolverFFI();
    } else {
      return new DnsResolverBinStr();
    }
  }
  
  public static function getTypeInt( string $type ): int {
    $type = strtoupper( $type );
    return array_keys( array_filter( static::$query_types, fn( $v ) => ( $v == $type ) ) )[0];
  }
  
  public static function getQueryClass( int $id ) {
    return static::$query_class[$id] ?? static::$query_class["default"];
  }
  
  public static function getQueryType( int $id ) {
    return static::$query_types[$id] ?? 'N/A';
  }
  
  protected static function decodeQueryId( string $binary_string ): int {
    return BinDecode::read_uint16( $binary_string, 0 );
  }
  
  protected static function decodeName( string $bin, $offset = 0 ): string {
    $parts = [];
    while ( BinDecode::read_uint8( $bin, $offset ) != 0 ) {
      if( BinDecode::read_uchar($bin,$offset) === "\xC0" ) {
        $ptr = BinDecode::read_uint16( $bin, $offset ) & 0x3fff;
        $parts[] = static::decodeName( $bin, $ptr );
        break;
      }
      
      $len = BinDecode::read_uint8( $bin, $offset );
      $parts[] = substr( $bin, ++$offset, $len );
      $offset = $offset + $len;
    }
    
    return implode( '.', $parts );
  }
  
  protected static function decodeIpv4Address( string $packet_bin, $offset ): string {
    return static::decodeAddress( $packet_bin, $offset, 32 );// 32 bit
  }
  
  protected static function decodeIpv6Address( string $packet_bin, $offset ): string {
    return static::decodeAddress( $packet_bin, $offset, 128 ); // 128bit
  }
  
  protected static function decodeAddress( string $packet_bin, $offset, $bit_size ): string {
    // overload 代替
    return inet_ntop( substr( $packet_bin, $offset, $bit_size/8 ) );
  }
  
  protected static function decodeTxt( string $packet_bin, int $offset, int $rdlength ): string {
    $txt = '';
    for ( $end_pos = $offset + $rdlength; $end_pos > $offset; $offset += $len + 1 ) {
      $len = BinDecode::uint8( $packet_bin[$offset] );;
      $txt .= substr( $packet_bin, $offset + 1, $len );
    }
    return $txt;
  }
  
  protected static function hex_dump( $data, $return = true, $newline = "\n", int $width = 12,
                                      string $pad = '.' ): ?string {
    static $from = '';
    static $to = '';
    
    //static $width = 16; # number of bytes per line
    //static $pad = '.'; # padding for non-visible characters
    
    if( $from === '' ) {
      for ( $i = 0; $i <= 0xFF; $i++ ) {
        $from .= chr( $i );
        $to .= ( $i >= 0x20 && $i <= 0x7E ) ? chr( $i ) : $pad;
      }
    }
    
    $hex = str_split( bin2hex( $data ), $width*2 );
    $chars = str_split( strtr( $data, $from, $to ), $width );
    
    $offset = 0;
    $str = '';
    foreach ( $hex as $i => $line ) {
      $str .= sprintf( '%06X', $offset )
        .' : '.implode( ' ', str_split( $line, 2 ) )
        .( strlen( $line ) == 32 ? '' : str_repeat( ' ', 32 + 15 - ( strlen( $line ) + ( strlen( $line )/2 - 1 ) ) ) )
        .' ['.sprintf( "%-16s", $chars[$i] ).']'.$newline;
      $offset += $width;
    }
    $return == false && print( $str );
    return $return ? $str : null;
  }
  
  protected static function decodeMx( $bin, $pos ): string {
    return static::decodeName( $bin, $pos + 2 );
  }
  
  protected static function hexdump_packet( string $bin, int $offset, int $len = null ) {
    dd( self::hex_dump( substr( $bin, $offset, $len ?? strlen( $bin ) ) ) );
  }
  
  protected static function decodeSoa( string $packet_bin, int $pos, int $rdlength ): array {
    $soa_rr_bin = substr( $packet_bin, $pos, $rdlength );
    $offset = 0;
    while ( BinDecode::read_uint8( $soa_rr_bin, $offset ) != 0 ) {
      if( BinDecode::read_uchar($soa_rr_bin,$offset) == "\xC0" ) {
        $offset = $offset + 1;
        break;
      }
      
      $len = BinDecode::read_uint8( $soa_rr_bin, $offset );
      $offset = $offset + $len + 1;
    }
    return [
      'mname'   => static::decodeName( $packet_bin, $pos ),
      'rname'   => static::decodeName( $packet_bin, $pos + $offset + 1 ),
      'serial'  => BinDecode::read_uint32(Bindecode::read_string($soa_rr_bin,$rdlength - 4*5,4),),
      'refresh' => BinDecode::read_uint32(Bindecode::read_string($soa_rr_bin,$rdlength - 4*4,4),),
      'retry'   => BinDecode::read_uint32(Bindecode::read_string($soa_rr_bin,$rdlength - 4*3,4),),
      'expire'  => BinDecode::read_uint32(Bindecode::read_string($soa_rr_bin,$rdlength - 4*2,4),),
      'min'     => BinDecode::read_uint32(Bindecode::read_string($soa_rr_bin,$rdlength - 4*1,4),),
    ];
  }
  
  protected static function parseResponseRecord( string $packet_bin, int $rr_pos ): array {
    /**
     * // レスポンス・レコード・データ・ヘッダ
     * typedef struct  __attribute__((packed)) {
     * uint16_t name;
     * uint16_t type;
     * uint16_t class;
     * uint32_t ttl;
     * uint16_t rdlength;
     * } dns_rr_header_t;
     */
    $rr = [];
    $offset = $rr_pos;
    if( Bindecode::read_string( $packet_bin, $rr_pos, 1 ) == "\xc0" ) {
      $alias_pos = BinDecode::read_uint16( $packet_bin, $offset ) & 0x3fff;
      $rr['name'] = static::decodeName( $packet_bin, $alias_pos );
      $offset = strpos( Bindecode::read_string( $packet_bin, $offset ), "\x00" ) + $rr_pos;
    } else if( BinDecode::read_uchar($packet_bin,$rr_pos) == "\x00" ) {
      $offset = $offset + 1;
      $rr['name'] = '';
    } else {
      $rr['name'] = static::decodeName( $packet_bin, $offset );
    }
    //
    $rr['type'] = BinDecode::read_uint16( $packet_bin, $offset );
    $rr['class'] = BinDecode::read_uint16( $packet_bin, $offset + 2 );
    $rr['ttl'] = BinDecode::read_uint32( $packet_bin, $offset + 2 + 2 );
    $rr['rdlength'] = BinDecode::read_uint16( $packet_bin, $offset + 2 + 2 + 4 );
    //
    $rr['rdata'] = match ( $rr['type'] ) {
      static::getTypeInt( "A" )     => static::decodeIpv4Address( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      static::getTypeInt( "AAAA" )  => static::decodeIpv6Address( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      static::getTypeInt( "TXT" )   => static::decodeTxt( $packet_bin, $offset + 2 + 2 + 4 + 2, $rr['rdlength'] ),
      static::getTypeInt( "NS" )    => static::decodeName( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      static::getTypeInt( "CNAME" ) => static::decodeName( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      static::getTypeInt( "SOA" )   => static::decodeSoa( $packet_bin, $offset + 2 + 2 + 4 + 2, $rr['rdlength'] ),
      static::getTypeInt( "MX" )    => static::decodeMX( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      static::getTypeInt( "PTR" )   => static::decodeName( $packet_bin, $offset + 2 + 2 + 4 + 2 ),
      //static::getTypeInt( "SRV" )   => static::decodeName( $binary_string, $pos + 2 + 2 + 2 + 4 + 2 ),//TODO
      default                       => bin2hex( substr( $packet_bin, $offset + 2 + 2 + 4 + 2, $rr['rdlength'] ) ),
    };
    return $rr;
  }
  
  protected static function send_query( string $binary_packet, string $ns_ip, int $timeout ) {
    $fp = @stream_socket_client( "udp://{$ns_ip}:53", $errno, $errstr, $timeout );
    // TODO::E_NS_SOCKET_FAILED の処理
    if( !$fp ) throw new \RuntimeException( "Socket Failed", 1 ); // E_NS_SOCKET_FAILED 代替
    stream_set_timeout( $fp, $timeout );
    fwrite( $fp, $binary_packet );
    $response = fread( $fp, 2048 );
    fclose( $fp );
    return $response;
  }
  
  public function resolve( string $name, string $type, string $ns_ip, int $timeout = 5 ) {
    $ret = static::query( $name, $type, $ns_ip, $timeout );
    foreach ( ['ANSWER', 'AUTHORITY', 'ADDITIONAL'] as $key ) {
      if(empty($ret[$key])) continue;
      foreach ( $ret[$key] as $idx => $record ) {
        $record['class'] = static::getQueryClass( $record['class'] );
        $record['type'] = static::getQueryType( $record['type'] );
        unset( $record['rdlength'] );
        //
        $ret[$key][$idx] = $record;
      }
    }
    return $ret;
  }
  
  /*
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * | 0| 1| 2| 3| 4| 5| 6| 7| 8| 9|10|11|12|13|14|15| <- index表見出し: ビット目盛り (計16ビット=2バイト)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                      ID                       | <- 乱数 :Transaction ID (2バイト)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   | <- クエリ種類：各種フラグ (計2バイト)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    QDCOUNT                    | <- クエリ数：質問数 (2バイト / 1以外は使わない。)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+       依頼の応答にExists と no Exists(NXDOMAIN)が交じると混乱する
   * |                    ANCOUNT                    | <- 回答リソースレコード数 (2バイト)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    NSCOUNT                    | <- 権威サーバーリソースレコード数 (2バイト)　
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   * |                    ARCOUNT                    | <- 追加情報リソースレコード数 (2バイト)
   * +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
   */
  abstract protected static function query( $name, $type, $ns_server, $timeout );
}