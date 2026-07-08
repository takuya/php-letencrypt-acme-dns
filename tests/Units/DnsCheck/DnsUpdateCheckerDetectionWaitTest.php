<?php

namespace DnsCheck;

use tests\TestCase;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;
use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\DnsCheck\Strategy\VoidWorkDnsCheck;

class DnsUpdateCheckerDetectionWaitTest extends TestCase {
  protected function build_mock_woker(callable $fn) {
    //$worker = new DnsCheckUpdateWorker();
    $mock = $this->getMockBuilder( DnsCheckUpdateWorker::class )
                 ->onlyMethods( ['canResolveDirectly'] )
                 ->getMock();
    $fn($mock);
    return $mock;
  }
  protected function dns_updater_wait_loop_shared_test( $worker):array {
    $sub_domain=RandomString::gen(4).'-phpunit';
    [$a, $b, $cnt] = [null, null, 0];
    try {
      //
      $worker->setTimeout( 1 );
      $worker->addCheck( 'google.com', // ここ固定。タイムアウト検出をテスト。
        'txt',
        function( $updated, $value ) use ( &$a, &$b, &$cnt ) { [$a = $value, $b = $updated, $cnt++]; }
      );
      $worker->waitDnsUpdate();
    } catch (\RuntimeException $e) {
      $this->assertStringContainsString( 'timeout', strtolower( $e->getMessage() ) );
    }
    
    return [$a,$b,$cnt];
    
  }
  public function test_dns_update_checker_wait_loop_using_local_resolver() {
    $mock = $this->build_mock_woker(function($mock){
      $mock->expects( $this->atLeastOnce() )->method( 'canResolveDirectly' )->willReturn( false );
    });
    $worker = $mock;
    [$a, $b, $cnt] = $this->dns_updater_wait_loop_shared_test($worker);
    $this->assertLessThan( 3, $cnt );
    $this->assertEquals( 'soa', $a['type'] );
    $this->assertIsNumeric( $a['serial'] );
  }
  public function test_dns_update_checker_wait_loop_using_directly_resolve() {
    $mock = $this->build_mock_woker(function($mock){
      $mock->expects( $this->atLeastOnce() )->method( 'canResolveDirectly' )->willReturn( true );
    });
    $worker = $mock;
    [$a, $b, $cnt] = $this->dns_updater_wait_loop_shared_test($worker);
    $this->assertLessThan( 3, $cnt );// タイムアウトしてるか
    $this->assertEquals( 'txt', $a['type'] );
    $this->assertIsString( $a['rdata'] );
  }
  public function test_dns_update_checker_wait_loop_no_check() {
    $mock = $this->getMockBuilder( DnsCheckUpdateWorker::class )
                 ->onlyMethods( ['selectStrategy'] )
                 ->getMock();
    $mock->expects( $this->atLeastOnce() )->method( 'selectStrategy' )->willReturn( VoidWorkDnsCheck::class );
    $worker = $mock;
    [$a, $b, $cnt] = $this->dns_updater_wait_loop_shared_test($worker);
    $this->assertLessThan( 3, $cnt );// タイムアウトしてるか
    $this->assertNull( $a['type'] );
    $this->assertNull( $a['time'] );
  }
  
}