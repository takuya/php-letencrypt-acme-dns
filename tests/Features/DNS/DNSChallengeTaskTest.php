<?php

namespace tests\Features\DNS;

use Takuya\LEClientDNS01\Delegators\AcmeDNSChallengeValue;
use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\DNSChallengeTask;
use function Takuya\Utils\is_wildcard_domain;
use function Takuya\Utils\parent_domain;
use PHPUnit\Framework\MockObject\Stub;


class DNSChallengeTaskTest extends CertTestCase {
  /**
   * @var AcmeDNSChallengeValue[]
   */
  protected array $challengeValues;
  
  protected function setUp(): void {
    parent::setUp();
    $rnd = RandomString::gen( 3, RandomString::LOWER );
    $this->challengeValues[]=$this->createAcmeStub("*.{$rnd}.{$this->base_domain1}");
    $this->challengeValues[] = $this->createAcmeStub("{$rnd}.{$this->base_domain1}");
  }
  
  /**
   * @param string $domain
   * @return AcmeDNSChallengeValue
   * @throws \PHPUnit\Framework\MockObject\Exception
   */
  protected function createAcmeStub(string $domain) {

    $obj = $this->createStub( AcmeDNSChallengeValue::class );
    $obj->method( 'acme_dns_record' )
        ->willReturn( [
          "_acme-challenge.".(is_wildcard_domain($domain)?parent_domain($domain):$domain),
          $dnsValue = RandomString::gen( 32, RandomString::ALPHA_NUM ),
        ] );
    $obj->method( 'getChallengeDomainName' )
        ->willReturn( $domain );
    $obj->method( 'getDnsValue' )
        ->willReturn( $dnsValue );
    $obj->method( 'getType' )
        ->willReturn( 'TXT' );
    return $obj;
  }
  
  public function test_update_dns_task(): void {
    $cf = new CloudflareDNSPlugin( $this->cf_api_token1, $this->base_domain1 );
    //dd($this->challengeValues[0]->acme_dns_record());
    $task = new DNSChallengeTask( $this->challengeValues, $cf );
    dd($task);
    
    
    $start=time();
    // TODO:: ここ続きが必要
    $task->start( fn( ...$e ) => dump( $e ) );
    dump($end=time()-$start);
    dump($end<$higher_limit_time);
  }
}
