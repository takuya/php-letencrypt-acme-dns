<?php

namespace tests\Features;

use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;

class WildcardCertificateTest extends CertTestCase {
  public function test_issue_wildcard_domain_certificate () {
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = [
      "*.{$str}.{$this->base_domain}",
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
  }
  
}