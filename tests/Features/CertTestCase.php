<?php

namespace tests\Features;

use tests\TestCase;
use tests\assertions\AssertCertificate;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;

class CertTestCase extends TestCase {
  use AssertCertificate;
  
  protected function getInstanceLetsEncryptAcmeDNS (): LetsEncryptAcmeDNS {
    return new LetsEncryptAcmeDNS( (new AsymmetricKey())->privKey(), $this->email );
  }
  
  protected function getInstanceCFDNSPlugin (): CloudflareDNSPlugin {
    $cf = new CloudflareDNSPlugin( $this->cf_api_token, $this->base_domain );
    $cf->enable_dns_check_at_waiting_for_update = true;
    return $cf;
  }
}