<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;

class ClientTest extends TestCase {
  
  public function test_le_sample () {
    $base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
    $cf_api_token = getenv( 'LE_SAMPLE_CLOUDFLARE_TOKEN' );
    $email = getenv( 'LE_SAMPLE_EMAIL' );
    $this->assertNotFalse( $base_domain );
    $this->assertNotFalse( $cf_api_token );
    
    $str = RandomString::gen( 5, RandomString::LOWER );
    $pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
    openssl_pkey_export( $pkey, $pkey_private_pem );
    $domain_name = "{$str}.{$base_domain}";
    $cf = new CloudflareDNSRecord( $cf_api_token, $domain_name );
    $cli = new LetsEncryptAcmeDNS( $pkey_private_pem, $email, $domain_name, $cf );
    $cert = $cli->orderNewCert();
    $this->assertArrayHasKey( 'public_key', $cert->toArray() );
    $this->assertArrayHasKey( 'private_key', $cert->toArray() );
    $this->assertArrayHasKey( 'certificate', $cert->toArray() );
    $this->assertArrayHasKey( 'intermediates', $cert->toArray() );
    
    $cert = new SSLCertificateInfo( $cert->toArray()['certificate'] );
    $this->assertStringContainsString("Let's Encrypt", $cert->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $cert->subject['commonName']);
  
    $ret = $cf->isExists( "_acme-challenge.{$domain_name}",'TXT');
    $this->assertFalse($ret);
  }
  
  
}