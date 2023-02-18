<?php

namespace tests\assertions;

use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;

trait AssertCertificate {
  public static function assertIsCert ( $cert_pem ): void {
    $ret = null;
    try {
      $ret = new SSLCertificateInfo( $cert_pem );
    } catch (\Exception $e) {
      $ret = $e;
    }
    static::assertThat( $ret, static::isInstanceOf( SSLCertificateInfo::class ), '' );
  }
  
  public static function assertLECertificateIssued ( $cert_pem, $domain_names ): void {
    $info = new SSLCertificateInfo( $cert_pem );
    static::assertStringContainsString( "Let's Encrypt", $info->issuer['organizationName'] );
    foreach ( $domain_names as $domain_name ) {
      static::assertStringContainsString( $domain_name, $info->extensions['subjectAltName'] );
    }
  }
  
  public static function assertIsPKCS12 ( $pkcs12, $pass = '' ): void {
    $ret = openssl_pkcs12_read( $pkcs12, $cert, $pass );
    static::assertTrue( $ret );
  }
  
  public static function assertPKCS12_PrivKeyMatched ( $expected_pkey, $pkcs12, $pass = '', ): void {
    openssl_pkcs12_read( $pkcs12, $c, $pass );
    static::assertEquals( trim( $expected_pkey ), trim( $c['pkey'] ) );
  }
  
  public static function assertPKCS12_CertMatched ( $expected_cert_pem, $pkcs12, $pass = '', ): void {
    openssl_pkcs12_read( $pkcs12, $c, $pass );
    static::assertEquals( trim( $expected_cert_pem ), trim( $c['cert'] ) );
  }
  
}