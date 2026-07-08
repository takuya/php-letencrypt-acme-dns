<?php

namespace tests\Units;

use tests\TestCase;
use function Takuya\Utils\dns_resolve;
use tests\assertions\AssertIPAddress;
use PHPUnit\Framework\Exception;
use function Takuya\Utils\is_local_dns_available;
use function Takuya\Utils\resolve_conf;
use Takuya\RandomString\RandomString;

class DNSResolveTest extends TestCase {
  use AssertIPAddress;
  
  /**
   * @throws \Exception dns resolve Exception
   */
  public function test_resolve_via_resolver() {
    $resolvers = ['8.8.8.8',/*'8.8.4.4'*/];
    foreach ( $resolvers as $resolver ) {
      try {
        $ret = dns_resolve( '.', 'ns', $resolver );
        $this->assertNotEmpty( $ret );
        $this->assertIsString( $ret );
        $this->assertStringContainsString( 'root-servers.net', $ret );
      } catch (\Exception $e) {
        throw new Exception( "udp/53 failed. Check connectivity to {$resolver}" );
      }
    }
  }
  
  public function test_resolve_dns_NS() {
    $ret = dns_resolve( '.', 'ns', 'a.root-servers.net' );
    $this->assertNotEmpty( $ret );
    $this->assertIsString( $ret );
    $this->assertStringContainsString( 'root-servers.net', $ret );
  }
  
  public function test_resolve_dns_SOA() {
    $ret = dns_resolve( 'g.co', 'soa' );
    $this->assertNotEmpty( $ret );
    $this->assertStringContainsString( 'google.com', $ret );
  }
  public function test_resolve_dns_unknonwn_domain_SOA() {
    $sub = RandomString::gen(4,RandomString::LOWER);
    $ret = dns_resolve( "{$sub}.google.com", 'soa' );
    $this->assertNotEmpty( $ret );
    $this->assertStringContainsString( 'google.com', $ret );
  }
  
  public function test_resolve_dns_TXT() {
    $ret = dns_resolve( 'gmail.com', 'txt' );
    $this->assertNotEmpty( $ret );
    $this->assertStringContainsString( 'v=spf1', $ret );
    $this->assertStringContainsString( 'smime', $ret );
  }
  
  public function test_resolve_dns_case_insensitive_TXT() {
    $ret = dns_resolve( 'gMaiL.com', 'txt' );
    $this->assertNotEmpty( $ret );
    $this->assertStringContainsString( 'v=spf1', $ret );
    $this->assertStringContainsString( 'smime', $ret );
  }
  
  public function test_resolve_dns_A() {
    $ret = dns_resolve( 'gmail.com', 'a' );
    $this->assertNotEmpty( $ret );
    $this->assertIsIPv4( explode( PHP_EOL, $ret )[0] );
  }
  
  public function test_resolve_dns_MX() {
    $ret = dns_resolve( 'gmail.com', 'mx' );
    $this->assertNotEmpty( $ret );
    $this->assertStringContainsString( 'google.com', $ret );
  }
  public function test_resolve_using_local_dns_server() {
    if (is_local_dns_available()){
      $server = resolve_conf()['nameserver'][0];
      $ret = dns_resolve('gmail.com', 'txt', $server);
      $this->assertNotEmpty($ret);
    }else{
      $this->assertFalse(file_exists('/etc/resolv.conf'));
    }
  }
  
  
}