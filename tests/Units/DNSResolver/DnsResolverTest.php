<?php

namespace DNSResolver;

use tests\TestCase;
use Takuya\LEClientDNS01\DnsResolver\DnsResolver;

class DnsResolverTest extends TestCase {
  public function test_edns_txt_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'google.com', 'txt', '1.1.1.1' );
    $this->assertGreaterThan( 512, $ret['PACKET_SIZE'] );
    $this->assertEquals( 'OPT', $ret['ADDITIONAL'][0]['type'] );
  }
  
  public function test_resolve_soa_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'google.com', 'soa', '1.1.1.1' );
    $this->assertEquals( 'google.com', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'SOA', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
    $this->assertArrayHasKey( 'mname', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'rname', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'serial', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'retry', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'expire', $ret['ANSWER'][0]['rdata'] );
    $this->assertArrayHasKey( 'min', $ret['ANSWER'][0]['rdata'] );
  }
  
  public function test_resolve_ns_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'google.com', 'ns', '1.1.1.1' );
    $this->assertEquals( 'google.com', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'NS', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
  }
  
  public function test_resolve_mx_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'gmail.com', 'mx', '1.1.1.1' );
    $this->assertEquals( 'gmail.com', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'MX', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
  }
  
  public function test_resolve_ptr_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( '8.8.8.8.in-addr.arpa', 'ptr', '1.1.1.1' );
    $this->assertEquals( '8.8.8.8.in-addr.arpa', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'PTR', $ret['ANSWER'][0]['type'] );
    $this->assertEquals( 'dns.google', $ret['ANSWER'][0]['rdata'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
  }
  
  public function test_resolve_cname_record() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'www.yahoo.co.jp', 'cname', '1.1.1.1' );
    $this->assertEquals( 'www.yahoo.co.jp', $ret['ANSWER'][0]['name'] );
    $this->assertEquals( 'CNAME', $ret['ANSWER'][0]['type'] );
    $this->assertGreaterThan( 0, $ret['ANSWER'][0]['ttl'] );
  }
  
  public function test_no_exists_domain() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'www.yahoo.co.jp', 'cname', 'ns1.google.com' );
    $this->assertEmpty( $ret['ANSWER'] );
  }
  
  public function test_connection_failed() {
    $resolver = DnsResolver::create( 'str' );
    $ret = $resolver->resolve( 'www.google.com', 'a', '1.1.1.1' );
    $not_dns_server = $ret['ANSWER'][0]['rdata'];
    $this->expectException( \RuntimeException::class );
    $resolver->resolve( 'www.google.com', 'a', $not_dns_server );
  }
  
  public function test_resolve_query_dot_root_server() {
    $resolver = DnsResolver::create();
    $ret = $resolver->resolve( '.', 'ns', '1.1.1.1' );
    $this->assertStringContainsString( 'root-servers.net', $ret['ANSWER'][0]['rdata'] );
    $this->assertStringContainsString( 'root-servers.net', $ret['ANSWER'][1]['rdata'] );
  }
  
  public function test_fqdn_trailing_dot_resolution() {
    $resolver = DnsResolver::create();
    $ret_1 = $resolver->resolve( 'co', 'ns', 'a.root-servers.net' );
    $ret_2 = $resolver->resolve( 'co.', 'ns', 'a.root-servers.net' );
    //
    usort( $ret_1['AUTHORITY'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    usort( $ret_2['AUTHORITY'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    $this->assertEquals( $ret_1['AUTHORITY'][0]['rdata'], $ret_2['AUTHORITY'][0]['rdata'] );
  }
  
  public function test_resolve_dot_to_root_server() {
    $resolver = DnsResolver::create();
    $ret_1 = $resolver->resolve( '.', 'ns', "a.root-servers.net" );
    $ret_2 = $resolver->resolve( '.', 'ns', dns_get_record( "a.root-servers.net", DNS_A )[0]['ip'] );
    usort( $ret_1['ADDITIONAL'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    usort( $ret_2['ADDITIONAL'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    $this->assertEquals( $ret_1['ADDITIONAL'][0]['rdata'], $ret_2['ADDITIONAL'][0]['rdata'] );
    usort( $ret_1['ANSWER'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    usort( $ret_2['ANSWER'], fn( $a, $b ) => $a['rdata'] <=> $b['rdata'] );
    $this->assertEquals( $ret_1['ANSWER'][0]['rdata'], $ret_2['ANSWER'][0]['rdata'] );
  }
}