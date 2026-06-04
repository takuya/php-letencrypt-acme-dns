<?php

namespace tests\Features\IssueCertificates;

use tests\Features\CertTestCase;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use function Takuya\Utils\domain_ns;
use function Takuya\Utils\sub_domain;
use function Takuya\Utils\is_wildcard_domain;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\parent_domain;

class MultipleAndWildcardCertificateTest extends CertTestCase {
  public function test_issue_multi_and_wildcard_domain_certificate () {
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $str = 'phpunit-'.$str;
    $domain_names = [
      "*.x.{$str}.{$this->base_domain}",
      "{$str}.{$this->base_domain}",
      "a.{$str}.{$this->base_domain}",
      "b.{$str}.{$this->base_domain}"
    ];
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