<?php


use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use tests\Features\CertTestCase;
use Takuya\LEClientDNS01\Account;

class PublicKeyPairTest extends CertTestCase {
  
  public function test_create_asymmetric_rsa_private_key() {
    $pkey = new AsymmetricKey();
    $priv = $pkey->privKey();
    $openssl_rsa = openssl_pkey_get_private($priv);
    $detail = openssl_pkey_get_details($openssl_rsa);
    $this->assertEquals($pkey->pubKey(), $detail['key']);
    $this->assertEquals(OPENSSL_KEYTYPE_RSA, $detail['type']);
    
  }
  public function test_create_asymmetric_ec_private_key() {
    openssl_pkey_export(openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_EC,'curve_name'=>'secp384r1'] ),$pem);
    $pkey = new AsymmetricKey($pem);
    $priv = $pkey->privKey();
    $openssl_rsa = openssl_pkey_get_private($priv);
    $detail = openssl_pkey_get_details($openssl_rsa);
    $this->assertEquals($pkey->pubKey(), $detail['key']);
    $this->assertEquals(OPENSSL_KEYTYPE_EC, $detail['type']);
  }
  
}