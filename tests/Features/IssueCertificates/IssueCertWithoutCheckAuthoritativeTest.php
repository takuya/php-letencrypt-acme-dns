<?php

namespace IssueCertificates;

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use tests\DebugLogger;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use tests\Features\IssueCertificates\IssueSingleDomainCertificateTest;

class IssueCertWithoutCheckAuthoritativeTest extends IssueSingleDomainCertificateTest {
  protected bool $enable_authoritative_dns_check = false;
  protected bool $enable_verbose_output = false;
  
  protected DebugLogger $logger;
  
  protected function log($name, $type, $content, $elapsed) {
    $this->logger = $this->logger ??  new DebugLogger( 'php://stderr' );
    $this->enable_verbose_output && $this->logger->log( sprintf(
      'dns wait ( %s, %s, %s...) updated TXT for %s sec .'.PHP_EOL,
      $name, $type, substr( $content, '0', 5 ),$elapsed ) );
  }
  
  public function test_single_domain_issue_cert() {
    // issue cert.
    $dns = $this->getInstanceCFDNSPlugin();
    $dns->enable_authoritative_check = $this->enable_authoritative_dns_check;//disable ns check.
    $cli = $this->getInstanceLetsEncryptAcmeDNS( $this->email );
    $cli->setDomainNames( $this->domain_names );
    $cli->setAcmeURL( LetsEncryptACMEServer::STAGING );
    $cli->setDnsPlugin( $dns );
    // request a SSL certificate.
    $time_elapsed = 0;
    $this->logger = new DebugLogger( 'php://stderr' );
    $new_cert = $cli->orderNewCert( null, function( $name, $type, $content, $elapsed ) use(&$time_elapsed) {
      $this->log($name, $type, $content,$elapsed );
      $time_elapsed=$elapsed;
    } );
    // assertion
    $this->assertGreaterThan($dns->time_try_resolve_after_update , $time_elapsed);
    $this->assertLessThan($dns->time_max_wait , $time_elapsed);
    $this->assertIsCert( $new_cert->cert() );
    $this->assertLECertificateIssued( $new_cert->cert(), $this->domain_names );
  }
  
}