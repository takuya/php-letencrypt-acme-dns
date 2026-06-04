<?php

namespace tests\Features\IssueCertificates;

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;

class MultipleDomainSubjectAltNamesCertTest extends CertTestCase {
  public function test_issue_multiple_domain_certificate () {
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $str = 'phpunit-'.$str;
    $domain_names = [
      "{$str}.{$this->base_domain}",
      "a.www.{$str}.{$this->base_domain}",
    ];
    // prepare
    $dns = $this->getInstanceCFDNSPlugin();
    $cli = $this->getInstanceLetsEncryptAcmeDNS("admin-{$str}@{$this->base_domain}");
    // start ACME
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