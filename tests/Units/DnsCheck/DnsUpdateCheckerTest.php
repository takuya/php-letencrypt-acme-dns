<?php

namespace DnsCheck;

use tests\TestCase;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;
use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\DnsCheck\Strategy\TTLFollowingDnsCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\SoaSerialDnsCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\DnsUpdateCheck;
use Takuya\LEClientDNS01\DnsCheck\Strategy\VoidWorkDnsCheck;

class DnsUpdateCheckerTest extends TestCase {
  protected function build_mock_woker( callable $fn ) {
    //$worker = new DnsCheckUpdateWorker();
    $mock = $this->getMockBuilder( DnsCheckUpdateWorker::class )
                 ->onlyMethods( ['selectStrategy'] )
                 ->getMock();
    $fn( $mock );
    return $mock;
  }
  
  protected string $base_domain;
  protected string $domain_name;
  protected string $api_token;
  protected object $api_client;
  protected string $sample_ip = '1.2.3.4';
  
  protected function setUp(): void {
    parent::setUp();
    $this->base_domain = getenv( 'LE_BASE_DOMAIN1' );
    $this->api_token = getenv( 'LE_CLOUDFLARE_TOKEN1' );
    $sub_domain = RandomString::gen( 4, RandomString::LOWER ).'-phpunit';
    $this->domain_name = "a.{$sub_domain}.{$this->base_domain}";
  }
  
  protected function getApiClient(): object {
    return $this->api_client ??= new CloudflareDNSRecord( $this->api_token, $this->base_domain );
  }
  
  protected function dns_updater_detection_test_shared( $worker ): array {
    [$a, $b, $cnt] = [null, null, 0];
    try {
      //
      $worker->addCheck(
        $this->domain_name,
        'A',
        function( $updated, $value ) use ( &$a, &$b, &$cnt ) {
          [$a = $value, $b = $updated, $cnt++];
          // dump( [$cnt => $b] );
        } );
      $this->add_dns_record( $this->domain_name, $this->sample_ip );
      $worker->waitDnsUpdate();
    } catch (\RuntimeException $e) {
      $this->assertStringContainsString( 'timeout', strtolower( $e->getMessage() ) );
    } finally {
      $this->del_dns_record( $this->domain_name );
    }
    
    
    return [$a, $b, $cnt];
  }
  
  protected function add_dns_record( $name, $ip ): bool {
    return $this->getApiClient()->addRecord( 'a', $name, $ip );
  }
  
  protected function del_dns_record( $name ): bool {
    $id = $this->getApiClient()->getRecordId( $name, 'a' );
    return $id && $this->getApiClient()->deleteRecord( $id );
  }
  
  public function test_dns_update_checker_following_ttl_using_local_resolver() {
    try {
      //$checker = new TTLFollowingDnsCheck( $this->domain_name, 'A' );
      $dummy_ttl = 3;
      $mock = $this->getMockBuilder( TTLFollowingDnsCheck::class )
                   ->onlyMethods( ['resolve'] )
                   ->disableOriginalConstructor()
                   ->setConstructorArgs([$this->domain_name, 'A'])
                   ->getMock();
      $ref = new \ReflectionProperty($mock,'values_at_start');
      $ref->setValue($mock,['domain' => $this->domain_name, 'type' => 'a', 'ttl' => $dummy_ttl]);
      $mock->expects( $this->atLeastOnce() )
           ->method( 'resolve' )
           ->willReturnCallback( function()use(&$dummy_ttl) { return ['domain' => $this->domain_name, 'type' => 'a', 'ttl' => $dummy_ttl--] ;});
      
      $checker = $mock;
      $checker->setLimit( $checker->getStartValue()['ttl'] );
      $fiber = $checker->checkTask( fn( ...$args ) => $args/**dump( $args )*/);
      //
      $this->add_dns_record( $this->domain_name, $this->sample_ip );
      //
      $fiber->start();
      $until = time() + $checker->getStartValue()['ttl'];
      while ( time() < $until ) {
        $fiber->resume();
        sleep( 1 );
      }
      $this->assertLessThan( 2, $checker->getLatestValue()['ttl'] );
    } catch (\ReflectionException $e) {
      throw $e;
    } finally {
      $this->del_dns_record( $this->domain_name );
    }
  }
  
  public function test_dns_update_checker_authoritative_server_using_local_resolver() {
    $mock = $this->build_mock_woker( function( $mock ) {
      $mock->expects( $this->atLeastOnce() )->method( 'selectStrategy' )->willReturn( SoaSerialDnsCheck::class );
    } );
    $worker = $mock;
    $worker->setTimeout( 60 );
    $worker->setInterval( 1 );
    [$a, $b, $cnt] = $this->dns_updater_detection_test_shared( $worker );
    $this->assertLessThan( 30, $cnt );
    $this->assertEquals( 'SOA', strtoupper( $a['type'] ) );
    $this->assertIsNumeric( $a['serial'] );
  }
  
  public function test_dns_update_checker_authoritative_server_using_directly_resolve() {
    $max_time = 30;
    $mock = $this->build_mock_woker( function( $mock ) use ( $max_time ) {
      $mock->expects( $this->atLeastOnce() )->method( 'selectStrategy' )->willReturn( DnsUpdateCheck::class );
    } );
    $worker = $mock;
    $worker->setTimeout( 60 );
    $worker->setInterval( 1 );
    [$a, $b, $cnt] = $this->dns_updater_detection_test_shared( $worker );
    $this->assertLessThan( $max_time + 1, $cnt );
    $this->assertEquals( 'A', strtoupper( $a['type'] ) );
    $this->assertNotEquals( $a['rdata'], $b['rdata'] );
    $this->assertIsString( $b['rdata'] = $this->sample_ip );
  }
  
}