<?php

namespace Takuya\LEClientDNS01\PKey;

class CertificateWithPrivateKey {
  public function __construct (
    protected string $priv_key_pem,
    protected string $cert_pem,
    protected array  $intermediates = [] ) {
  }
  
  public function toArray (): array {
    return [
      'certificate' => $this->cert_pem,
      'intermediates' => $this->intermediates,
      'private_key' => $this->priv_key_pem,
      'public_key' => ( new AsymmetricKey( $this->priv_key_pem ) )->pubKey(),
    ];
  }
  
  
}