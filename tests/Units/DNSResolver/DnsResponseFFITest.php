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
  protected function expectedResponseParsedData() {
    return   [
      0=>["name" => "g.co","type" => 2, "class" => 1, "ttl" => 345600, "rdlength" => 16, "rdata" => "ns4.google.com",],
      1=>["name" => "g.co","type" => 2, "class" => 1, "ttl" => 345600, "rdlength" => 6, "rdata" => "ns3.google.com",],
      2=>["name" => "g.co","type" => 2, "class" => 1, "ttl" => 345600, "rdlength" => 6, "rdata" => "ns1.google.com",],
      3=>["name" => "g.co","type" => 2, "class" => 1, "ttl" => 345600, "rdlength" => 6, "rdata" => "ns2.google.com",],
    ];
  
  }
  public  function decodeName(string $bin, $offset=0){
    $parts = [];
    
    while ( unpack("C",$bin[$offset])[1] != 0 ) {
      $len = unpack("C",$bin[$offset])[1];
      $offset++;
      $parts[] = substr($bin, $offset,$len);
      $offset = $offset+$len;
      // 圧縮を探す。
      if ($bin[$offset]=="\xC0"){
        $ptr = unpack('n', substr($bin, $offset, 2))[1] & 0x3fff;
        $parts[]=$this->decodeName($bin,$ptr);
        break;
      }
      
    }
    return implode( '.', $parts );
  }
  public function parseResponseRecord( $binary_string, $pos) {
    $rr = ['name'=>null,'type'=>null];
    if( substr($binary_string,$pos,1) == "\xc0"){
      $alias = ord(substr($binary_string,$pos+1,1));
      $rr['name'] = $this->decodeName($binary_string,$alias);
    }
    $rr['type'] = unpack('n', substr($binary_string, $pos+2, 2))[1];
    //$pos += 2;
    $rr['class'] = unpack('n', substr($binary_string, $pos+2+2, 2))[1];
    //$pos += 2;
    $rr['ttl'] = unpack('N', substr($binary_string, $pos+2+2+2, 4))[1];
    //$pos += 4;
    $rr['rdlength'] = unpack('n', substr($binary_string, $pos+2+2+2+4, 2))[1];
    //
    $rr['rdata'] = $this->decodeName($binary_string,$pos+2+2+2+4+2);
    return $rr;
  
  }
  
  
  public function test_parse_ns_response() {
    $ffi = $this->dns_ffi();
    $response_ffi = $ffi->new( "dns_packet_t" );
    FFI::memcpy( FFI::addr( $response_ffi ), $this->sample_packet(), strlen( $this->sample_packet() ) );
    
    
    $ancount = $ffi->htons( $response_ffi->ancount );
    $qdcount = $ffi->htons( $response_ffi->qdcount );
    for (
      $ptr=$ffi->cast('char *', FFI::addr($response_ffi)), $i =FFI::sizeof($ffi->type( "dns_header_t" ));
      $i<FFI::sizeof($ffi->type( "dns_packet_t" ));
      $i++
    ) {
      if (FFI::string( $ptr[$i], 1 ) == "\x00" ){
        $qname_end_pos = $i;
        break;
      }
    }
    $ans_start_pos = $qname_end_pos +1+ 2 + 2;

    //
    $packet_addr = $ffi->cast( 'uint8_t *',FFI::addr($response_ffi) );
    
    
    $answer_pos =[];
    for ( $offset=$ans_start_pos, $i=0;$i<$ancount;$i++){
      $answer_pos[]=$offset;
      $a = $ffi->cast("dns_rr_header_t *", FFI::addr($packet_addr[$offset]));
      $rdlength=$ffi->htons($a->rdlength);
      $offset += 12 + $rdlength;
    }
    //dd($answer_pos);
    // ここからが本番。
    
    $bin = FFI::string(FFI::addr( $response_ffi ),FFI::sizeof($ffi->type('dns_packet_t')));
    $ans = [];
    foreach ($answer_pos as $pos){
      $ans[]=$this->parseResponseRecord($bin,$pos);
    }
    
    $this->assertSame($this->expectedResponseParsedData(), $ans);
    
    
  }
}