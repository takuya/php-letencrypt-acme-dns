<?php

namespace tests\Units;

use tests\TestCase;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Delegators\CloudflareDNSRecord;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;

class ClientTest extends TestCase {
  public function test_wildcard_and_base_domain_multi_cert(){
    $base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
    $cf_api_token = getenv( 'LE_CLOUDFLARE_TOKEN' );
    $email = getenv( 'LE_SAMPLE_EMAIL' );
    $cf = new CloudflareDNSRecord( $cf_api_token, $base_domain );
    $cf->enable_dns_check_at_waiting_for_update=true;
    $ownerPkey = new AsymmetricKey();
    
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["{$str}.{$base_domain}","*.{$str}.{$base_domain}"];
    
    $cli = new LetsEncryptAcmeDNS($ownerPkey->privKey() , '',$domain_names, $cf );
    $cert_and_a_key = $cli->orderNewCert();
    $info = new SSLCertificateInfo($cert_and_a_key->cert());
    $this->assertArrayHasKey( 'public_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'private_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'certificate', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'intermediates', $cert_and_a_key->toArray() );
    
    $cert = new SSLCertificateInfo( $cert_and_a_key->toArray()['certificate'] );
    $this->assertStringContainsString("Let's Encrypt", $cert->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $cert->subject['commonName']);
    foreach ( $domain_names as $domain_name ) {
      $this->assertStringContainsString($domain_name,  $cert->extensions['subjectAltName']);
    }
  }
  
  public function test_wildcard_domain_cert(){
    $base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
    $cf_api_token = getenv( 'LE_SAMPLE_CLOUDFLARE_TOKEN' );
    $email = getenv( 'LE_SAMPLE_EMAIL' );
    $cf = new CloudflareDNSRecord( $cf_api_token, $base_domain );
    $cf->enable_dns_check_at_waiting_for_update=true;
    $ownerPkey = new AsymmetricKey();
    
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["*.{$str}.{$base_domain}"];
    
    $cli = new LetsEncryptAcmeDNS($ownerPkey->privKey() , '',$domain_names, $cf );
    $cert_and_a_key = $cli->orderNewCert();
    $info = new SSLCertificateInfo($cert_and_a_key->cert());
    $this->assertArrayHasKey( 'public_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'private_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'certificate', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'intermediates', $cert_and_a_key->toArray() );
    
    $cert = new SSLCertificateInfo( $cert_and_a_key->toArray()['certificate'] );
    $this->assertStringContainsString("Let's Encrypt", $cert->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $cert->subject['commonName']);
    foreach ( $domain_names as $domain_name ) {
      $this->assertStringContainsString($domain_name,  $cert->extensions['subjectAltName']);
    }
  }
  public function test_multi_domain_cert(){
    $base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
    $cf_api_token = getenv( 'LE_SAMPLE_CLOUDFLARE_TOKEN' );
    $email = getenv( 'LE_SAMPLE_EMAIL' );
    $cf = new CloudflareDNSRecord( $cf_api_token, $base_domain );
    $cf->enable_dns_check_at_waiting_for_update=true;
    $ownerPkey = new AsymmetricKey();
  
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["{$str}.{$base_domain}","a.www.{$str}.{$base_domain}",/*"*.{$str}.{$base_domain}"*/];

    $cli = new LetsEncryptAcmeDNS($ownerPkey->privKey() , $email,$domain_names, $cf );
    $cert_and_a_key = $cli->orderNewCert();
    $info = new SSLCertificateInfo($cert_and_a_key->cert());
    $this->assertArrayHasKey( 'public_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'private_key', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'certificate', $cert_and_a_key->toArray() );
    $this->assertArrayHasKey( 'intermediates', $cert_and_a_key->toArray() );
  
    $cert = new SSLCertificateInfo( $cert_and_a_key->toArray()['certificate'] );
    $this->assertStringContainsString("Let's Encrypt", $cert->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $cert->subject['commonName']);
    foreach ( $domain_names as $domain_name ) {
      $this->assertStringContainsString($domain_name,  $cert->extensions['subjectAltName']);
    }
  }
  public function test_le_signle_domain () {
    $base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
    $cf_api_token = getenv( 'LE_SAMPLE_CLOUDFLARE_TOKEN' );
    $email = getenv( 'LE_SAMPLE_EMAIL' );
    $cf = new CloudflareDNSRecord( $cf_api_token, $base_domain );
    $cf->enable_dns_check_at_waiting_for_update=true;
    $ownerPkey = new AsymmetricKey();
  
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_names = ["{$str}.{$base_domain}"];
  
    $cli = new LetsEncryptAcmeDNS($ownerPkey->privKey() , $email,$domain_names, $cf );
    $new_cert = $cli->orderNewCert();
    $this->assertArrayHasKey( 'public_key', $new_cert->toArray() );
    $this->assertArrayHasKey( 'private_key', $new_cert->toArray() );
    $this->assertArrayHasKey( 'certificate', $new_cert->toArray() );
    $this->assertArrayHasKey( 'intermediates', $new_cert->toArray() );
    // cert attributes.
    $cert_info = new SSLCertificateInfo( $new_cert->cert() );
    $this->assertStringContainsString("Let's Encrypt", $cert_info->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $cert_info->subject['commonName']);
    foreach ( $domain_names as $domain_name ) {
      $this->assertStringContainsString($domain_name,  $cert_info->extensions['subjectAltName']);
    }
    // pkcs12
    $pass = RandomString::gen( 15, RandomString::LOWER );
    $str = $new_cert->pkcs12($pass );
    openssl_pkcs12_read($str,$c, $pass);
    $this->assertEquals(trim($new_cert->privKey()),trim($c['pkey']));
    $this->assertEquals(trim($new_cert->cert()),trim($c['cert']));
    // renew
    $renew_cert = $cli->orderNewCert($new_cert->privKey());
    $renew_info = new SSLCertificateInfo( $renew_cert->cert() );
    $this->assertStringContainsString("Let's Encrypt", $renew_info->issuer['organizationName']);
    $this->assertStringContainsString($base_domain,  $renew_info->subject['commonName']);
    foreach ( $domain_names as $domain_name ) {
      $this->assertStringContainsString($domain_name,  $renew_info->extensions['subjectAltName']);
    }
    $this->assertEquals($new_cert->privKey(),$renew_cert->privKey());
    
    
  }
  
}