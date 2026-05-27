<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use Takuya\LEClientDNS01\Acme\Http\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\X509SSLCertificate;
use Takuya\LEClientDNS01\Acme\Resources\AcmeRevokeCertReason;

class RevokeCertDirectoryRequest extends AcmeDirectoryRequest {
  
  protected string $method = 'POST';
  protected int $reason;
  
  public function __construct(
    protected AcmeNonce           $nonce,
    protected AcmeAccount         $account,
    protected \OpenSSLCertificate $cert,
    protected string              $endpoint_url,
    AcmeRevokeCertReason          $reason,
  ) {
    //
    $this->setReason( $reason );
  }
  
  public function setReason( AcmeRevokeCertReason $reason ): void {
    $this->reason = $reason->value;
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => Rs256JwsSigner::sign( $p1, $p2, $this->account->private_key_pem() ),
    ] );
    return $body;
  }
  
  protected function payloadString(): string {
    openssl_x509_export( $this->cert, $pem );
    $payload = [
      // DER を base64url
      'certificate' => Base64URLEncode::encode( X509SSLCertificate::convertPemToDer( $pem ) ),
      // optional
      // 0 unspecified
      // 1 keyCompromise
      // 4 superseded
      // 5 cessationOfOperation
      'reason'      => $this->reason,
    ];
    return Base64URLEncode::encode( json_encode( $payload ) );
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
}