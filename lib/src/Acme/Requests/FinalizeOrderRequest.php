<?php

namespace Takuya\LEClientDNS01\Acme\Requests;

use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\Acme\Base64URLEncode;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;

class FinalizeOrderRequest extends AcmeRequest {
  
  public string $method = 'POST';
  
  public function __construct(
    protected AcmeOrder    $order,
    protected ?AcmeAccount $account,
    protected AcmeNonce    $nonce,
    protected string       $csr_pem,
  ) {
  }
  
  protected function protectedStr(): string {
    return parent::encodeObject( [
      "alg"   => "RS256",
      "kid"   => $this->account->kid(),
      "nonce" => $this->nonce->content(), // 取得済みの Nonce
      "url"   => $this->resource_url(),
    ] );
  }
  
  protected function resource_url() {
    return $this->getRequestUrl();
  }
  
  public function getBody(): string {
    $body = json_encode( [
      "protected" => $p1 = $this->protectedStr(),
      "payload"   => $p2 = $this->payloadString(),
      "signature" => $this->signatureString( $p1, $p2 ),
    ] );
    return $body;
  }
  
  
  public function getRequestUrl(): string {
    return $this->order->getFinalizeUrl();
  }
  protected function __payload(): array {
    //// PEMからヘッダー/フッター、改行を除去してバイナリに戻す
    //// 正規表現で ---BEGIN--- と ---END--- の間のベース64部分だけを抜く
    $innerBase64 = preg_replace( '/\-+BEGIN CERTIFICATE REQUEST\-+/', '', $this->csr_pem );
    $innerBase64 = preg_replace( '/\-+END CERTIFICATE REQUEST\-+/', '', $innerBase64 );
    $innerBase64 = trim( $innerBase64 );
    //// 3. 一旦バイナリ(DER)にデコード
    $csrDer = base64_decode( $innerBase64 );
    //// 4. それを再度「Base64URL」形式でエンコード（パディング無し）
    $csrBase64Url = Base64URLEncode::encode( $csrDer );
    return $payload = ["csr" => $csrBase64Url];
    
  }
  protected function signatureString( $protectedStr, $payloadStr ) {
    return static::signature( $protectedStr, $payloadStr, $this->account->private_key_pem() );
  }
  protected function payloadString() {
    return Base64URLEncode::encode(json_encode($this->__payload()));
  }
}