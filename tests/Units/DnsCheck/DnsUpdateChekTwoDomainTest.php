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
use Takuya\LEClientDNS01\DnsResolver\DnsResolver;
use Takuya\LEClientDNS01\DnsCheck\ResolveConf;
use function Takuya\Utils\is_directly_resolve_allowed;

class DnsUpdateChekTwoDomainTest extends TestCase {
  
  protected string $base_domain;
  protected array $domain_names;
  protected string $api_token;
  protected object $api_client;
  protected array $sample_ips = ['1.2.3.4', '5.6.7.8'];
  
  protected function setUp(): void {
    parent::setUp();
    $this->base_domain = getenv( 'LE_BASE_DOMAIN1' );
    $this->api_token = getenv( 'LE_CLOUDFLARE_TOKEN1' );
    $sub_domain = RandomString::gen( 4, RandomString::LOWER ).'-phpunit';
    $this->domain_names = ["a.{$sub_domain}.{$this->base_domain}", "b.{$sub_domain}.{$this->base_domain}"];
  }
  
  protected function getApiClient(): object {
    return $this->api_client ??= new CloudflareDNSRecord( $this->api_token, $this->base_domain );
  }
  
  protected function add_dns_record( $name, $ip ): bool {
    return $this->getApiClient()->addRecord( 'a', $name, $ip );
  }
  
  protected function del_dns_record( $name ): bool {
    $id = $this->getApiClient()->getRecordId( $name, 'a' );
    return $id && $this->getApiClient()->deleteRecord( $id );
  }
  
  public function test_detect_two_domain_record_updated() {
    if (!is_directly_resolve_allowed($this->domain_names[0])){
      $this->markTestSkipped('DNS(53/udp) resolve not available: op53b');
    }
    try {
      $mock = $this->getMockBuilder( DnsCheckUpdateWorker::class )->onlyMethods( ['selectStrategy'] )->getMock();
      $mock->expects( $this->atLeastOnce() )->method( 'selectStrategy' )->willReturn( DnsUpdateCheck::class );
      $worker = $mock;
      $debug_callback = function($b,$a,$cnt){
        dump( [$cnt=>['updated'=>$b['rdata']!==$a['rdata'],'last'=>$b]] );
      };
      $worker->addCheck( $this->domain_names[0], 'A', $debug_callback );
      $worker->addCheck( $this->domain_names[1], 'A', $debug_callback );
      $worker->setTimeout( 60 );
      $worker->setInterval( 1 );
      //
      $this->add_dns_record( $this->domain_names[0], $this->sample_ips[0] );
      $this->add_dns_record( $this->domain_names[1], $this->sample_ips[1] );
      //
      $worker->waitDnsUpdate();
      //
      $this->del_dns_record( $this->domain_names[0] );
      $this->del_dns_record( $this->domain_names[1] );
      //
      $ret = [
        DnsResolver::resolveDomainName( $this->domain_names[0], 'A', '1.1.1.1' ),
        DnsResolver::resolveDomainName( $this->domain_names[1], 'A', '1.1.1.1' ),
      ];
      $this->assertEquals( $this->sample_ips[0], $ret[0]['ANSWER'][0]['rdata'] );
      $this->assertEquals( $this->sample_ips[1], $ret[1]['ANSWER'][0]['rdata'] );
    } finally {
      // ensure remove record.
      $this->del_dns_record( $this->domain_names[0] );
      $this->del_dns_record( $this->domain_names[1] );
    }
  }
}