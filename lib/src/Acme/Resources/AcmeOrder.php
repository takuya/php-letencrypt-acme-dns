<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

use Psr\Http\Message\ResponseInterface;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Requests\FinalizeOrderRequest;
use Takuya\LEClientDNS01\Acme\Requests\FinalizeOrderStatusRequest;

class AcmeOrder {
  protected string $url;
  protected string $certificate;
  protected AcmeAccount $account;
  
  public function __construct(
    protected string $status,
    protected string $expires,
    protected array  $identifiers,
    protected array  $authorizations,
    protected string $finalize,
  ) {
  }
  
  public function updateOrderProperty( string $key, string $value ): false|string {
    return property_exists( $this, $key ) ? $this->$key = $value : false;
  }
  
  public function updateStatus( string $stat ): false|string {
    return $this->updateOrderProperty( 'status', $stat );
  }
  
  public function setOrderUrl( string $url ): void {
    $this->url = $url;
  }
  public function setAccount(AcmeAccount $account): void {
    $this->account = $account;
  }
  public function getAccount():AcmeAccount {
    return $this->account;
  }
  
  public function getOrderUrl(): string {
    return $this->url;
  }
  
  public function getCertificateUrl(): string {
    if( $this->status != 'valid' ) {
      throw new \RuntimeException( 'certificate download url can be access after finalize is valid.' );
    }
    return $this->certificate;
  }
  
  public static function parse( string|ResponseInterface $new_order_response ): static {
    $body = is_string( $new_order_response ) ? $new_order_response : $new_order_response->getBody()->getContents();
    $obj = json_decode( $body );
    return new static( $obj->status, $obj->expires, $obj->identifiers, $obj->authorizations, $obj->finalize );
  }
  
  public function __toString(): string {
    return $this->toJson();
  }
  
  public function toJson(): string {
    return json_encode( $this->toArray() );
  }
  
  public function toArray() {
    return [
      'status'         => $this->status,
      'expires'        => $this->expires,
      'identifiers'    => $this->identifiers,
      'authorizations' => $this->authorizations,
      'finalize'       => $this->finalize,
      'certificate'    => $this->certificate ?? null,
      'url'            => $this->url ?? null,
    ];
  }
  
  public function getFinalizeUrl(): string {
    return $this->finalize;
  }
  
  public function getAuthorization( $identifier_value ): AcmeAuthorization {
    $idx = -1;
    foreach ( $this->identifiers as $key => $identifier ) {
      if( strcasecmp( $identifier_value, $identifier->value ) === 0 ) {
        $idx = $key;
        break;
      }
    }
    return new AcmeAuthorization( $identifier_value, $this->authorizations[$idx], $this );
  }
  
  public function createFinalizeRequest( AcmeAccount $account, AcmeNonce $nonce,
                                         string      $csr_pem ): FinalizeOrderRequest {
    return new FinalizeOrderRequest( $this, $account, $nonce, $csr_pem );
  }
  
  public function createFinalizeStatusCheckRequest(): FinalizeOrderStatusRequest {
    return new FinalizeOrderStatusRequest( $this );
  }
  
  public function updateLocation( ResponseInterface $res ) {
    $this->url = $res->getHeaderLine( 'Location' );
    return $this->url;
  }
  
}