<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;

class ChallengeAuthorizeRequest extends AcmeRequest {
  public function __construct(
    protected AcmeNonce                   $nonce,
    protected ?AcmeAccount                $account = null,
    protected ?AcmeAuthorizationChallenge $challenge = null,
    protected string                      $method = 'POST' ) {
    //
  }
  
  protected function protectedStr(): string {
    return parent::encodeObject( [
      "alg"   => "RS256",
      "kid"   => $this->account->kid(),
      "nonce" => $this->nonce->content(),      // 取得済みの Nonce
      "url"   => $this->challenge->getUrl(),   // orderから取得したURL
    ] );
  }
  
  protected function payloadStr(): string {
    return parent::encodeObject( (object)[] );
  }
  protected function signatureStr( $protectedStr, $payloadStr ):string {
    return static::signature( $protectedStr, $payloadStr, $this->account->private_key_pem() );
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadStr(),
      "signature" => $this->signatureStr( $p1, $p2 ),
    ] );
    return $body;
  }
  
  public function getRequestUrl(): string {
    return $this->challenge->getUrl();
  }
}