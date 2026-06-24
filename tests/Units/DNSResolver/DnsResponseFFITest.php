<?php

namespace DNSResolver;

use tests\TestCase;
use \FFI;

class DnsResponseFFITest extends TestCase {
  
  protected function dns_ffi() {
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
    ";
    $ffi = FFI::cdef( $cdef, "libc.so.6" );
    
    return $ffi;
    
  }
  protected function sample_packet() {
    $sample_response_packet_binary =
      "286885000001000400000008016702636f0000020001c00c0002000100054600".
      "0010036e733406676f6f676c6503636f6d00c00c00020001000546000006036e".
      "7333c026c00c00020001000546000006036e7331c026c00c0002000100054600".
      "0006036e7332c026c02200010001000546000004d8ef260ac022001c00010005".
      "460000102001486048020038000000000000000ac03e00010001000546000004".
      "d8ef240ac03e001c00010005460000102001486048020036000000000000000a".
      "c05000010001000546000004d8ef200ac050001c000100054600001020014860".
      "48020032000000000000000ac06200010001000546000004d8ef220ac062001c".
      "00010005460000102001486048020034000000000000000a";
    
    $response = hex2bin($sample_response_packet_binary);
    return $response;
  }
  public  function decodeName(string $bin, $offset=0){
    $parts = [];
    
    while ( unpack("C",$bin[$offset])[1] != 0 ) {
      $len = unpack("C",$bin[$offset])[1];
      $offset++;
      $parts[] = substr($bin, $offset,$len);
      $offset = $offset+$len;
    }
    return implode( '.', $parts );
  }
  public function decodeLabel(string $bin , int $offset=0) {
  
  }
  
  
  public function test_parse_ns_response() {
    $ffi = $this->dns_ffi();
    $response_ffi = $ffi->new( "dns_packet_t" );
    FFI::memcpy( FFI::addr( $response_ffi ), $this->sample_packet(), strlen( $this->sample_packet() ) );
    
    
    $ancount = $ffi->htons( $response_ffi->ancount );
    $qdcount = $ffi->htons( $response_ffi->qdcount );
    
    $qname_start_pos = $qname_pos=FFI::sizeof($ffi->type( "dns_header_t" ));
    
    $addr = $ffi->cast('char *', FFI::addr( $response_ffi ));
    
    for ( $offset=$qname_start_pos; $offset<FFI::sizeof($ffi->type( "dns_packet_t" ));$offset++ ){
      
      dd(FFI::string( $addr, 10 ));
      
      
      
    }
    while ( unpack("C",$bin[$offset])[1] != 0 ) {
      $len = unpack("C",$bin[$offset])[1];
      $offset++;
      $parts[] = substr($bin, $offset,$len);
      $offset = $offset+$len;
    }


    $ans_start_addr =
      FFI::sizeof($ffi->type( "dns_header_t" ))
      +strlen($qname)
      +2
    ;
    
    dd($ans_start_addr);

    
    //$addr = $addr + 12;
    //$cnt = 0;
    while(FFI::string($addr++,1)!=0){
      dump(FFI::string($addr,1));
      $cnt++;
    }
    //(self::hex_dump(FFI::string($addr,1)));
    dd('end', $cnt);
    //while ( $response_ffi->data[$offset] != 0 ) {
    //  $offset += $response_ffi->data[$offset] + 1;
    //}
    //
    //
    //

    //dd( self::hex_dump( FFI::string( , 200 ) ) );
    for ( $i = 0; $i < $ancount; $i++ ) {
      //dd(self::hex_dump() ));
      //$ip_offset = $offset + 12;
      $rr = $ffi->cast(
        'dns_rr_header_t*',
        FFI::addr( $response_ffi->data[$offset] )
      );
      $rdlength = $ffi->htons( $rr->rdlength );
      $rdata_pos = $offset + 12;
      $rdata = $ffi->cast(
        'uint8_t*',
        FFI::addr( $response_ffi->data[$rdata_pos] )
      );

      dd($rdata_pos);
      //ここだね
      //$ret = $this->decodeName(FFI::string( FFI::addr( $response_ffi->data[$rdata_pos] ), $rdlength ),0);
      
      
      $r_header_size = $ffi::sizeof( $response_ffi ) - $ffi::sizeof( $response_ffi->data );
      dump($ffi->htons( $rr->name ));
      $name_addr_val = $ffi->htons( $rr->name ) - $r_header_size;
      dd( ( $name_addr_val & 0xC000 ) === 0xC000 );
      
      //if( ( $name_addr_val & 0xC000 ) === 0xC000 ) {
      //  $ptr = $name_addr_val & 0x3FFF;
      //
      //  $name = $this->decodeName(
      //    FFI::string(FFI::addr($response_ffi),FFI::sizeof($response_ffi)),
      //    $ptr+FFI::sizeof($ffi->type('dns_header_t'))
      //  );
      //}
      dump( [
        $name,
        match ( $ffi->htons( $rr->type ) ) {
          1 => "A",            // IPv4
          2 => "NS",           // ネームサーバ
          5 => "CNAME",        // 別名
          6 => "SOA",          // Zone情報
          12 => "PTR",         // 逆引き
          15 => "MX",          // メールサーバ
          16 => "TXT",         // テキスト
          28 => "AAAA",        // IPv6
          33 => "SRV",         // サービス
          257 => "CAA",        // 証明書発行制御
        },
        match ( $ffi->htons( $rr->class ) ) {
          1 => "IN",
          3 => "CHAOS",
          4 => "HS",
          default => 'ANY'
        },
        match ($ffi->htons( $rr->type )) {
          1  => inet_ntop($rdata),              // A
          28 => inet_ntop($rdata),              // AAAA
          16 => $rdata,                   // TXT
          2  => $rdata,         // NS
          5  => $rdata,         // CNAME
          default => bin2hex($rdata),
        },
      ] );
      
      $offset = $offset + 12 + $rdlength;
    }

    
  }
}