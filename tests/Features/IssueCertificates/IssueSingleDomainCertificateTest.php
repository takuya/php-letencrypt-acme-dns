<?php

namespace tests\Features\IssueCertificates;

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use tests\DebugLogger;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\Account;
use Takuya\LEClientDNS01\DnsCheck\DnsCheckUpdateWorker;
use function Takuya\Utils\dns_resolve;

class IssueSingleDomainCertificateTest extends CertTestCase {
  protected string $email;
  protected array $domain_names;
  
  protected function setUp(): void {
    parent::setUp();
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["phpunit-{$str}.{$this->base_domain}"];
    $this->domain_names = $domain_names;
    $this->email = "admin-{$str}@{$this->base_domain}";
  }
  
  public function test_issue_single_domain_san_cert_can_be_valid() {
    //// issue cert.
    $dns = $this->getInstanceCFDNSPlugin();
    $cli = $this->getInstanceLetsEncryptAcmeDNS( $this->email );
    $pkey = ( new AsymmetricKey() )->privKey();
    $cli->setLogger( new DebugLogger( 'php://stderr' ) );
    $cli->setDomainNames( $this->domain_names );
    $cli->setAcmeURL( LetsEncryptACMEServer::STAGING );
    $cli->setDnsPlugin( $dns );
    // request a DV-SSL certificate.
    $new_cert = $cli->orderNewCert($pkey);
    //// assertion
    $this->assertIsCert( $new_cert->cert() );
    $this->assertLECertificateIssued( $new_cert->cert(), $this->domain_names );
    //
    //// pkcs12 assertion
    $pass = RandomString::gen( 15, RandomString::LOWER );
    $pkcs = $new_cert->pkcs12( $pass );
    $this->assertIsPKCS12( $pkcs, $pass );
    $this->assertPKCS12_PrivKeyMatched( $new_cert->privKey(), $pkcs, $pass );
    $this->assertPKCS12_CertMatched( $new_cert->cert(), $pkcs, $pass );
    // ------------------
    // clean up DNS and assertion.
    // ------------------
    $cli->waitForCleanupDns();
    foreach ($cli->getLastChallengeDnsValue() as $d => $v){
      $ret = dns_resolve($d,'TXT');
      $this->assertStringNotContainsString($v,$ret);
    }
    // ------------------
    // renew certificate
    // ------------------
    $cert_pkey = $new_cert->privKey();
    $cli->orderNewCert($cert_pkey);
    $renew_cert = $cli->getLastIssuedCertificate();
    $this->assertIsCert( $renew_cert->cert() );
    $this->assertNotEquals(
      (new SSLCertificateInfo($renew_cert->fullChain()))->serialNumber,
      (new SSLCertificateInfo($new_cert->fullChain()))->serialNumber
    );
    $this->assertEquals(
      (new SSLCertificateInfo($renew_cert->fullChain()))->extensions['subjectAltName'],
      (new SSLCertificateInfo($new_cert->fullChain()))->extensions['subjectAltName'],
    );
  }
  
}