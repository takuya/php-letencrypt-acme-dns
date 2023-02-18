<?php

namespace tests\Features;

use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;

class IssueSingleDomainCertificateTest extends CertTestCase {
  
  public function test_single_domain_issue_cert () {
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = [
      "{$str}.{$this->base_domain}",
    ];
    // prepare
    $dns = $this->getInstanceCFDNSPlugin();
    $cli = $this->getInstanceLetsEncryptAcmeDNS();
    $cli->setDomainNames( $domain_names );
    $cli->setAcmeURL( LetsEncryptACMEServer::STAGING );
    $cli->setDnsPlugin( $dns );
    // request a SSL certificate.
    $new_cert = $cli->orderNewCert();
    // assertion
    $this->assertIsCert( $new_cert->cert() );
    $this->assertLECertificateIssued( $new_cert->cert(), $domain_names );
    
    // pkcs12
    $pass = RandomString::gen( 15, RandomString::LOWER );
    $pkcs = $new_cert->pkcs12( $pass );
    $this->assertIsPKCS12( $pkcs, $pass );
    $this->assertPKCS12_PrivKeyMatched( $new_cert->privKey(), $pkcs, $pass );
    $this->assertPKCS12_CertMatched( $new_cert->cert(), $pkcs, $pass );
    // renew
    $renew_cert = $cli->orderNewCert( $new_cert->privKey() );
    $this->assertIsCert( $renew_cert->cert() );
    $this->assertLECertificateIssued( $renew_cert->cert(), $domain_names );
  }
  
}