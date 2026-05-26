<?php

namespace Takuya\LEClientDNS01\Acme\Requests;


use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpoint;

class RegisterNewAccountDirectoryRequest extends AcmeDirectoryRequest {
  public function __construct(
    AcmeNonce    $nonce,
    AcmeAccount  $account,
    AcmeEndpoint $resource = null,
    string       $method = 'POST' ) {
    parent::__construct( $nonce, $account, $resource, $method );
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => $this->signatureString( $p1, $p2 ),
    ] );
    return $body;
  }
  
  protected function protectedStr(): string {
    return parent::protected( parent::jwt( $this->account->private_key_pem() ), $this->nonce->content(), $this->resource_url() );
  }
  
  protected function payloadString(): string {
    return parent::payload( [
      "termsOfServiceAgreed" => true,
      "contact"              => ["mailto:{$this->account->email()}"],
    ] );
  }
  
  protected function signatureString( $protectedStr, $payloadStr ) {
    return AcmeDirectoryRequest::signature( $protectedStr, $payloadStr, $this->account->private_key_pem() );
  }
  
}