<?php

namespace tests\Features\IssueCertificates;

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use tests\DebugLogger;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;

class IssueSingleDomainCertificateTest extends CertTestCase {
  protected string $email;
  protected array $domain_names;
  protected bool $enable_authoritative_dns_check = true;
  protected bool $enable_verbose_output = false;
  
  protected function setUp(): void {
    parent::setUp();
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["phpunit-{$str}.{$this->base_domain}"];
    $this->domain_names = $domain_names;
    $this->email = "admin-{$str}@{$this->base_domain}";
  }
  
  public function test_single_domain_issue_cert() {
    // issue cert.
    $dns = $this->getInstanceCFDNSPlugin();
    $dns->enable_authoritative_check = $this->enable_authoritative_dns_check;
    $cli = $this->getInstanceLetsEncryptAcmeDNS( $this->email );
    $this->enable_verbose_output && $cli->setLogger( new DebugLogger( 'php://stderr' ) );
    $cli->setDomainNames( $this->domain_names );
    $cli->setAcmeURL( LetsEncryptACMEServer::STAGING );
    $cli->setDnsPlugin( $dns );
    // request a SSL certificate.
    $new_cert = $cli->orderNewCert();
    // assertion
    $this->assertIsCert( $new_cert->cert() );
    $this->assertLECertificateIssued( $new_cert->cert(), $this->domain_names );
    
    // pkcs12 assertion
    $pass = RandomString::gen( 15, RandomString::LOWER );
    $pkcs = $new_cert->pkcs12( $pass );
    $this->assertIsPKCS12( $pkcs, $pass );
    $this->assertPKCS12_PrivKeyMatched( $new_cert->privKey(), $pkcs, $pass );
    $this->assertPKCS12_CertMatched( $new_cert->cert(), $pkcs, $pass );

    // renew certificate
    $renew_cert = $cli->orderNewCert( $new_cert->privKey() );


    // assert renewed.
    $this->assertIsCert( $renew_cert->cert() );
    $this->assertNotEquals(
      (new SSLCertificateInfo($renew_cert->fullChain()))->serialNumber,
      (new SSLCertificateInfo($new_cert->fullChain()))->serialNumber
    );
    $this->assertLECertificateIssued( $renew_cert->cert(), $this->domain_names );
  }
  
}