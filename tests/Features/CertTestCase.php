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
  protected string $base_domain;
  protected string $cf_api_token;
  protected string $base_domain1;
  protected string $cf_api_token1;
  protected string $base_domain2;
  protected string $cf_api_token2;
  protected string $email;
  
  protected function getInstanceLetsEncryptAcmeDNS (): LetsEncryptAcmeDNS {
    return new LetsEncryptAcmeDNS( (new AsymmetricKey())->privKey(), $this->email );
  }
  
  protected function getInstanceCFDNSPlugin (): CloudflareDNSPlugin {
    $cf = new CloudflareDNSPlugin( $this->cf_api_token, $this->base_domain );
    $cf->enable_dns_check_at_waiting_for_update = true;
    return $cf;
  }
  protected function setUp (): void {
    parent::setUp();
    $env_keys = [
      'base_domain' => 'LE_BASE_DOMAIN1',
      'cf_api_token' => 'LE_CLOUDFLARE_TOKEN1',
      //
      'base_domain1' => 'LE_BASE_DOMAIN1',
      'cf_api_token1' => 'LE_CLOUDFLARE_TOKEN1',
      //
      'base_domain2' => 'LE_BASE_DOMAIN2',
      'cf_api_token2' => 'LE_CLOUDFLARE_TOKEN2',
      'email' => 'LE_SAMPLE_EMAIL',
    ];
    foreach ( $env_keys as $name => $env_key ) {
      $this->{$name} = getenv( $env_key );
    }
  }
  
}