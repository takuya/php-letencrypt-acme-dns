<?php

namespace Takuya\LEClientDNS01\PKey;

class AsymmetricKey {
  protected string $pkey_private;
  
  public function __construct ( string $private_key_pem = null ) {
    $private_key_pem = $private_key_pem ?? self::create_priv_key();
    self::check_private_key( $private_key_pem );
    $this->pkey_private = $private_key_pem;
  }
  
  public static function create_priv_key (): string {
    $pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
    openssl_pkey_export( $pkey, $pkey_private_pem );
    return $pkey_private_pem;
  }
  
  public static function check_private_key ( string $priv_key ): void {
    //assert PEM, by test can be loaded
    if ( !openssl_pkey_get_private( $priv_key ) ) {
      throw new \RuntimeException( 'failed to load private key' );
    }
  }
  
  public function pubKey () {
    return openssl_pkey_get_details( openssl_pkey_get_private( $this->pkey_private ) )['key'];
  }
  
  public static function CertificateSigningRequest ( array $dn, \OpenSSLAsymmetricKey $private_key,
                                                     array $options = null,
                                                     array $extra = null ): \OpenSSLCertificateSigningRequest|bool {
    return openssl_csr_new( $dn, $private_key, $options, $extra );
  }
  
  public function privKey (): string {
    openssl_pkey_export( $this->pkey_private, $pem );
    return $pem;
  }
  
}