<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Http\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;

class StartNewOrderDirectoryRequest extends AcmeDirectoryRequest {
  protected array $domains = [];
  
  public function __construct(
    protected AcmeNonce   $nonce,
    protected AcmeAccount $account,
    protected string      $endpoint_url,
    protected string      $method = 'POST' ) {
    //
    $this->method = 'POST';
  }
  
  public function addCertificateRequestDomain( $domain ): void {
    $this->domains[] = $domain;
  }
  
  protected function protectedStr(): string {
    return Base64URLEncode::encode( json_encode( [
      "alg"   => "RS256",
      "kid"   => $this->account->kid(),
      "nonce" => $this->nonce->content(),     // 取得済みの Nonce
      "url"   => $this->getRequestUrl(),      // Directoryから取得したURL
    ] ) );
  }
  
  public function getRequestUrl(): string {
    return $this->endpoint_url;
  }
  
  
  protected function payloadString(): string {
    // payload は次のような構造が求められる。
    // type=dns は DV証明書を示すので、ここは固定。 challenge type とは別物。
    //  $payload = [
    //    "identifiers" => [
    //     ["type" => "dns", "value" => 'example.tld'],
    //    ],
    //  ];
    $payload = [
      'identifiers' => array_map( fn( $e ) => ["type" => "dns", "value" => $e], $this->domains ),
    ];
    return Base64URLEncode::encode( json_encode( $payload ) );
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => Rs256JwsSigner::sign( $p1, $p2, $this->account->private_key_pem() ),
    
    ] );
    return $body;
  }
}