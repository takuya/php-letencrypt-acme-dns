<?php

namespace Takuya\LEClientDNS01\Acme;

use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\Acme\Http\Base64URLEncode;

class X509SSLCertificate {
  
  
  protected string $certificate;
  
  public function __construct( string $cert_pem ) {
    $this->certificate = $cert_pem;
  }
  
  public function getOpenSSLCertificate(): \OpenSSLCertificate {
    return openssl_x509_read( $this->certificate );
  }
  
  public function exportLeafPem(): string {
    // 中間証明書の削除. return main certificate .
    openssl_x509_export( $this->getOpenSSLCertificate(), $pem );
    return $pem;
  }
  
  public function intermediatesAsPem(): string {
    $arr = $this->toArray();
    $intermediates = $arr['intermediates'];
    return implode( PHP_EOL, $intermediates );
  }
  
  public function fullChainCerts(): array {
    return array_values( array_filter( array_map(
      fn( $pem ) => openssl_x509_read( $pem ),
      static::splitChains( $this->certificate )
    ) ) );
  }
  
  public function fullChainCertPem(): string {
    return implode( '', array_map( function( $c ) {
      openssl_x509_export( $c, $p );
      if( !$p ) {
        throw new \RuntimeException( "invalid certificate." );
      }
      return $p;
    }, $this->fullChainCerts() ) );
  }
  
  public function acme_cert_id():string {
    return sprintf("%s.%s",
      Base64URLEncode::encode( hex2bin( str_replace( ':', '', $this->authorityKeyIdentifier() ) ) ),
      Base64URLEncode::encode( hex2bin( $this->serial() ) ));
  }
  public function authorityKeyIdentifier() {
    return openssl_x509_parse( $this->certificate )['extensions']['authorityKeyIdentifier'];
  }
  public function serial() {
    return openssl_x509_parse( $this->certificate )['serialNumberHex'];
  }
  
  public function __toString() {
    return $this->fullChainCertPem();
  }
  
  public function export(): string {
    return $this->__toString();
  }
  
  public function toArray(): array {
    return static::splitCertChain( $this->certificate );
  }
  
  public function certInfo(): SSLCertificateInfo {
    return new SSLCertificateInfo( $this->certificate );
  }
  
  public function isFullChain(): bool {
    return sizeof( static::splitChains( $this->certificate ) ) > 1;
  }
  
  public static function splitChains( string $cert_pem ): array {
    preg_match_all(
      '/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s',
      $cert_pem,
      $matches
    );
    return $matches[0];
  }
  
  public static function splitCertChain( string $full_chain_cert_pem ): array {
    $certs = static::splitChains( $full_chain_cert_pem );
    return [
      'leaf'          => $certs[0],
      'intermediates' => array_slice( $certs, 1 ),
    ];
  }
  
  public static function convertPemToDer( string $certificate_pem ): string {
    $certificate_pem = trim( $certificate_pem );
    $cert_body = preg_replace(
      '/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/',
      '',
      $certificate_pem
    );
    
    $certificate_der = base64_decode( $cert_body );
    return $certificate_der;
  }
}