<?php

namespace Takuya\LEClientDNS01\Acme\Requests;


use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Http\JWT;
use Takuya\LEClientDNS01\Acme\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;

class RegisterNewAccountDirectoryRequest extends AcmeDirectoryRequest {
  public function __construct(
    protected AcmeNonce   $nonce,
    protected AcmeAccount $account,
    protected string      $endpoint_url,
    protected string      $method = 'POST' ) {
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => Rs256JwsSigner::sign( $p1, $p2, $this->account->private_key_pem() ),
    ] );
    return $body;
  }
  
  public function getRequestUrl(): string {
    return $this->endpoint_url;
  }
  
  
  protected function protectedStr(): string {
    return Base64URLEncode::encode( json_encode( [
      "alg"   => "RS256",
      "jwk"   => JWT::toArray( $this->account->private_key_pem() ),
      "nonce" => $this->nonce->content(),     // 取得済みの Nonce
      "url"   => $this->getRequestUrl(),   // Directoryから取得したURL
    ] ) );
  }
  
  protected function payloadString(): string {
    return Base64URLEncode::encode( json_encode( [
      "termsOfServiceAgreed" => true,
      "contact"              => ["mailto:{$this->account->email()}"],
    ] ) );
  }
  
}