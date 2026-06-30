<?php

namespace DNSResolver;

use tests\TestCase;
use Takuya\LEClientDNS01\DnsResolver\Binary\BinDecode;

class BinDecodeHexDumpTest extends TestCase {
  
  public function test_hexdump_binary_string() {
    
    foreach (range(10,128,10) as $byte_size ){
      $bytes = join('',array_map(fn()=>random_bytes(1),range(0,$byte_size)));
      $ret = BinDecode::hexdump($bytes);
      $this->assertEquals(($byte_size+16>>4)+1 , substr_count($ret,"\n") );
    }
    // 表示幅を変える
    foreach (range(10,16) as $col_size ){
      $bytes = join('',array_map(fn()=>random_bytes(1),range(1,33)));
      $ret = BinDecode::hexdump($bytes,0,null, $col_size);
      $this->assertEquals( intval((32/$col_size))+2 , substr_count($ret,"\n") );
    }
    //// ずらしたとき 先頭ずらし
    $bytes = join('',array_map(fn()=>random_bytes(1),range(0,31)));
    $ret = BinDecode::hexdump($bytes,16);
    $this->assertEquals(2 , substr_count($ret,"\n") );
    $this->assertMatchesRegularExpression('/^000010:/' , explode("\n", $ret)[1] );
    //// ずらしたとき 先頭ずらし、長さ指定
    $bytes = join('',array_map(fn()=>random_bytes(1),range(1,64)));
    $ret = BinDecode::hexdump($bytes,48,16);
    $this->assertEquals(2 , substr_count($ret,"\n") );
    $this->assertMatchesRegularExpression('/^000030:/' , explode("\n", $ret)[1] );
    ////切り出しサイズ指定。
    $bytes = join('',array_map(fn($e)=>chr($e),range(1,32)));
    $ret = BinDecode::hexdump($bytes,0,2);
    $this->assertMatchesRegularExpression('/^000000: 01 02\s+\[..\s+]$/', explode("\n", $ret)[1] );
    // ずらして、切り出しサイズ指定
    $bytes = join('',array_map(fn($e)=>chr($e),range(0,99)));
    $ret = BinDecode::hexdump($bytes,1, 2);
    $this->assertMatchesRegularExpression('/^000000:\s{4}01 02\s+\[\s..\s+]$/', explode("\n", $ret)[1] );
    // ずらして切り出しサイズ指定して１行目をスキップ
    $bytes = join('',array_map(fn($e)=>chr($e),range(0,99)));
    $ret = BinDecode::hexdump($bytes,16, 2);
    $this->assertMatchesRegularExpression('/^000010: 10 11\s+\[..\s+]$/', explode("\n", $ret)[1] );
    // colsize =12, offset=12,len=12
    $bytes = join('',array_map(fn($e)=>chr($e),range(0,99)));
    $ret = BinDecode::hexdump($bytes,12, 12,12);
    $this->assertEquals('00000c: 0c 0d 0e 0f 10 11 12 13 14 15 16 17   [............]', explode("\n", $ret)[1] );
    $bytes = join('',array_map(fn($e)=>chr($e),range(0,99)));
    $ret = BinDecode::hexdump($bytes,13, 24,12);
    $this->assertMatchesRegularExpression('/^000024: 24\s+\[\$\s+]$/', explode("\n", $ret)[3] );
  }
  public function test_hexdump_out_of_bound() {
    $bytes = join('',array_map(fn($e)=>chr($e),range(0,99)));
    $ret = BinDecode::hexdump($bytes,90,11);
    $this->assertMatchesRegularExpression('/^000060: 60 61 62 63\s+\[`abc\s{12}]$/', explode("\n", $ret)[2] );
    $ret = BinDecode::hexdump($bytes,90,-1);
    $this->assertMatchesRegularExpression('/^000060: 60 61 62 63\s+\[`abc\s{12}]$/', explode("\n", $ret)[2] );
    $ret = BinDecode::hexdump($bytes,90,-1,12);
    $this->assertMatchesRegularExpression('/^000060: 60 61 62 63\s+\[`abc\s{8}]$/', explode("\n", $ret)[2] );
  }
}