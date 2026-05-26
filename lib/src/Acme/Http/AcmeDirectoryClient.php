<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Psr\Http\Message\ResponseInterface;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\StartNewOrderDirectoryRequest;

class AcmeDirectoryClient {
  
  public function __construct( protected AcmeDirectory $dir ) { }
  
  /**
   * @return AcmeNonce
   */
  public function newNonce(): AcmeNonce {
    $req = $this->dir->getResource( AcmeEndpointEnum::newNonce )->createRequest();
    $acme_nonce = $req->getNonce();
    $res = AcmeHttpClient::send( $req );
    static::updateNonce( $acme_nonce, $res );
    return $acme_nonce;
  }
  
  /**
   * @param AcmeAccount $account
   * @param string|null $nonce
   * @return array{account_url:string,new_nonce:string}
   */
  public function newAccount( AcmeAccount $account, AcmeNonce $nonce ): array {
    $req = $this->dir->getResource( AcmeEndpointEnum::newAccount )->createRequest( $nonce, $account );
    $res = AcmeHttpClient::send( $req );
    $nonce->updateNonce($res);
    $kid = static::updateAccount( $account, $res );
    return ['new_nonce' => $nonce->content(), 'account_url' => $kid,];
  }
  
  /**
   * @param AcmeAccount $account
   * @param array       $domains
   * @param string|null $nonce
   * @return array{new_order:object,new_nonce:string,order_url:string}
   */
  public function newOrder( AcmeAccount $account, array $domains, AcmeNonce $nonce ): array {

    /** @var StartNewOrderDirectoryRequest $req */
    $req = $this->dir->getResource( AcmeEndpointEnum::newOrder )->createRequest( $nonce, $account );
    foreach ( $domains as $domain ) {
      $req->addCertificateRequestDomain( $domain );
    }
    //
    $res = AcmeHttpClient::send( $req );
    $nonce->updateNonce($res);
    $body = json_decode( $res->getBody()->getContents() );
    return ['new_order' => $body, 'new_nonce' => $nonce->content(), 'order_url' => $res->getHeaderLine( 'Location' )];
  }
  public static function updateNonce( AcmeNonce $nonce, ResponseInterface $res ): string {
    if($nonce->updateNonce( $res )){
      return $nonce->content();
    }
    throw new \BadMethodCallException("http response does not contain Reply-Nonce");
  }
  
  public static function updateAccount( AcmeAccount $account, ResponseInterface $res ): string {
    $account->updateAccountUrl( $res );
    if (empty($kid =$account->kid())){
      throw new \BadMethodCallException("HTTP response does not contain Location(kid)");
    }
    return $kid;
  }
  
}