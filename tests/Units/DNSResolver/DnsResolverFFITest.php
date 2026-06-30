<?php

namespace DNSResolver;

use tests\TestCase;
use Takuya\LEClientDNS01\DnsResolver\DnsResolver;

class DnsResolverFFITest extends TestCase {
  
  public function test_resolve_using_ffi() {
    $resolver = DnsResolver::create( 'ffi' );
    // dig a g.co @1.1.1.1
    $ret = $resolver->resolve( 'g.co', 'a', '1.1.1.1' );
    $this->assertEquals( 'g.co', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'A', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
    $this->assertNotFalse( ip2long( $ret['ANSWER'][0]['rdata'] ) );
    // dig txt g.co @1.1.1.1
    $ret = $resolver->resolve( 'g.co', 'txt', '1.1.1.1' );
    $this->assertEquals( 'g.co', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'TXT', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
    // dig aaaa g.co @1.1.1.1
    $ret = $resolver->resolve( 'g.co', 'aaaa', '1.1.1.1' );
    $this->assertEquals( 'g.co', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'AAAA', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
    $this->assertNotFalse( inet_pton( $ret['ANSWER'][0]['rdata'] ) );
    // dig soa g.co @1.1.1.1
    $ret = $resolver->resolve( 'g.co', 'soa', '1.1.1.1' );
    $this->assertEquals( 'g.co', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'SOA', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
    $this->assertArrayHasKey( 'mname', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'rname', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'serial', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'retry', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'expire', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'min', $ret['ANSWER'][0]['rdata'] );
    // dig ns g.co @1.1.1.1
    $ret = $resolver->resolve( 'g.co', 'ns', '1.1.1.1' );
    $this->assertEquals( 'g.co', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'NS', $ret['ANSWER'][0]['type'] );
    $this->assertNotEmpty( $ret['ANSWER'][0]['rdata'] );
    // dig -x 1.1.1.1
    $ret = $resolver->resolve( '1.1.1.1.in-addr.arpa', 'ptr', '1.1.1.1' );
    $this->assertEquals( '1.1.1.1.in-addr.arpa', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'PTR', $ret['ANSWER'][0]['type'] );
    $this->assertEquals( 'one.one.one.one', $ret['ANSWER'][0]['rdata'] );
  }
  //public function test_resolve_fallback_to_tcp_ffi() {
  //  dig DNSKEY . @a.root-servers.net  +dnssec
  //  $resolver = DnsResolver::create();
  //  //$resolver->resolve('google.com','AAAA','1.1.1.1');
  //  $ret = $resolver->resolve('google.com','dnskey','a.root-servers.net');
  //  dump($ret);
  //  dump('end');
  //
  //}
}