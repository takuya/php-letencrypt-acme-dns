<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpoint;

class StartNewOrderDirectoryRequest extends  AcmeDirectoryRequest {
  protected array $domains=[];
  protected string $method = 'POST';
  public function __construct(
    AcmeNonce     $nonce,
    ?AcmeAccount  $account = null,
    ?AcmeEndpoint $resource = null,
    string        $method = 'POST' ) {
    //
    $this->method = 'POST';
    parent::__construct( $nonce, $account, $resource, $this->method );
  }
  public function addCertificateRequestDomain($domain) {
    $this->domains[] = $domain;
  }
  protected function protectedStr(): string {
    return parent::encodeObject([
      "alg"   => "RS256",
      "kid"   => $this->account->kid(),
      "nonce" => $this->nonce->content(), // 取得済みの Nonce
      "url"   => $this->resource_url(),   // Directoryから取得したURL
    ]);
  }
  protected function payloadString() {
    // payload は次のような構造が求められる。 type=dns は DV証明書を示すので、ここは固定。challenge type とは別物。
    //  $payload = [
    //    "identifiers" => [
    //     ["type" => "dns", "value" => 'example.tld'],
    //    ],
    //  ];
    $payload=[
      'identifiers' =>array_map(fn($e)=>["type" => "dns", "value" => $e], $this->domains),
    ];
    return parent::encodeObject($payload);
  }
  protected function signatureString( $protectedStr, $payloadStr ) {
    return static::signature( $protectedStr, $payloadStr, $this->account->private_key_pem() );
  }

  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => $this->signatureString( $p1, $p2 ),
    ] );
    return $body;
  }
  
  
}