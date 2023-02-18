<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;

class RequestIssueBeforeReadyTest extends TestCase {
  
  public function test_get_ready_status_request_issue_cert () {
    $ownerPkey = new AsymmetricKey();
    $dns = $this->createStub( CloudflareDNSPlugin::class );
    //
    $cli = new LetsEncryptAcmeDNS( $ownerPkey->privKey(), $this->email );
    $this->assertGotException( function() use ( $cli ) { $cli->isReady(); }, \LogicException::class );
    //
    $cli->setDomainNames( ['example.tld'] );
    $this->assertGotException( function() use ( $cli ) { $cli->isReady(); }, \LogicException::class );
    //
    $cli->setDnsPlugin( $dns );
    $this->assertNotGotException( function() use ( $cli ) { $cli->isReady(); } );
  }
  
}