<?php

namespace Takuya\LEClientDNS01\PKey;

class CertificateWithPrivateKey {
  public function __construct (
    protected string $priv_key_pem,
    protected string $cert_pem,
    protected array  $intermediates = [] ) {
  }
  public function pubKey(){
    return ( new AsymmetricKey( $this->priv_key_pem ) )->pubKey();
  }
  public function privKey(){
    return $this->priv_key_pem;
  }
  public function cert(){
    return $this->cert_pem;
  }
  public function fullChain(){
    $items = [$this->cert(),...$this->intermediates];
    return implode(PHP_EOL,$items);
  }
  
  public function toArray (): array {
    return [
      'certificate' => $this->cert_pem,
      'intermediates' => $this->intermediates,
      'private_key' => $this->privKey(),
      'public_key' => $this->pubkey(),
    ];
  }
  
  
}