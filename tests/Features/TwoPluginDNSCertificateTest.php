<?php

namespace tests\Features;

use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;

class TwoPluginDNSCertificateTest extends CertTestCase {
  public function test_issue_two_domain_two_dns_plugin_certificate () {
    
    // variables
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = [
      "*.{$str}.{$this->base_domain1}",
      "*.{$str}.{$this->base_domain2}",
    ];
    // prepare
    $cli = $this->getInstanceLetsEncryptAcmeDNS();
    $cli->setDomainNames( $domain_names );
    $cli->setAcmeURL( LetsEncryptACMEServer::STAGING );
    // set dns plugin per domain.
    $dns_plugin_1 = new CloudflareDNSPlugin( $this->cf_api_token1, $this->base_domain1 );
    $dns_plugin_2 = new CloudflareDNSPlugin( $this->cf_api_token2, $this->base_domain2 );
    $cli->setDnsPlugin( $dns_plugin_1, $this->base_domain1 );
    $cli->setDnsPlugin( $dns_plugin_2, $this->base_domain2 );
    // request a SSL certificate.
    $new_cert = $cli->orderNewCert();
    // assertion
    $this->assertIsCert( $new_cert->cert() );
    $this->assertLECertificateIssued( $new_cert->cert(), $domain_names );
  }
  
}