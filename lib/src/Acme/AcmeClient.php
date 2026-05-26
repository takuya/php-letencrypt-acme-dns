<?php

namespace Takuya\LEClientDNS01\Acme;

use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Takuya\LEClientDNS01\Acme\Requests\AcmeNonce;
use Psr\Http\Message\ResponseInterface;
use Takuya\LEClientDNS01\Acme\Requests\StartNewOrderDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;

/**
 * 全体の流れをここで管理する。
 */
class AcmeClient {
  protected AcmeNonce $nonce;
  
  public function __construct( protected AcmeDirectory $dir ) { }
  
  public function newNonce(): AcmeNonce {
    $req = $this->dir->getResource( AcmeEndpointEnum::newNonce )->createRequest();
    $this->nonce = $req->getNonce();
    $cli = new AcmeHTTPClient();
    $res = $cli->send( $req );
    static::updateNonce( $this->nonce, $res );
    return $this->nonce;
  }
  
  public static function updateNonce( AcmeNonce $nonce, ResponseInterface $res ): string {
    $nonce->updateNonce( $res );
    return $nonce->content();
  }
  
  public static function updateAccount( AcmeAccount $account, ResponseInterface $res ): string {
    return $account->updateAccountUrl( $res );
  }
  
  public static function updateOrder( AcmeOrder $order, ResponseInterface $res ): string {
    return $order->updateLocation( $res );
  }
  
  public function newAccount( AcmeAccount $account, ?string $nonce = null ): array {
    $this->nonce = $nonce ? new AcmeNonce( $nonce ) : $this->nonce;
    $cli = new AcmeHTTPClient();
    $req = $this->dir->getResource( AcmeEndpointEnum::newAccount )->createRequest( $this->nonce, $account );
    $res = $cli->send( $req );
    $nonce = static::updateNonce( $this->nonce, $res );
    $kid = static::updateAccount( $account, $res );
    return ['new_nonce' => $nonce, 'account_url' => $kid,];
  }
  
  public function newOrder( AcmeAccount $account, array $domains, ?string $nonce = null ) {
    $this->nonce = $nonce ? new AcmeNonce( $nonce ) : $this->nonce;
    $cli = new AcmeHTTPClient();
    /** @var StartNewOrderDirectoryRequest $req */
    $req = $this->dir->getResource( AcmeEndpointEnum::newOrder )->createRequest( $this->nonce, $account );
    foreach ( $domains as $domain ) {
      $req->addCertificateRequestDomain( $domain );
    }
    //
    $res = $cli->send( $req );
    $nonce = static::updateNonce( $this->nonce, $res );
    $body = json_decode( $res->getBody()->getContents() );
    return ['order' => $body, 'nonce' => $nonce, 'order_url' => $res->getHeaderLine( 'Location' )];
  }
  
  public function challengeAuthorization( AcmeAuthorizationChallenge $challenge, AcmeAccount $account,
                                          ?string                    $nonce ) {
    $this->nonce = $nonce ? new AcmeNonce( $nonce ) : $this->nonce;
    $req = $challenge->createRequest( $this->nonce, $account );
    $cli = new AcmeHTTPClient();
    $res = $cli->send( $req );
    static::updateNonce( $this->nonce, $res );
    $obj = json_decode( $res->getBody()->getContents() );
    return ['response' => $obj, 'nonce' => $this->nonce->content()];
  }
  
  protected function checkChallengeAuthorizationResult( AcmeAuthorizationChallenge $challenge ) {
    $req = $challenge->createRequestForCheckPendingResult();
    $cli = new AcmeHTTPClient();
    $res = $cli->send( $req );
    $obj = json_decode( $res->getBody()->getContents() );
    return $obj;
  }
  
  public function waitForAuthorization( AcmeAuthorizationChallenge $challenge, ?callable $call_on_wait = null ) {
    $max_wait_sec = 30;
    $until = time() + $max_wait_sec;
    do {
      // Order の最新状態を取得
      $orderData = $this->checkChallengeAuthorizationResult( $challenge );
      $status = $orderData->status;
      //dump($orderData);
      
      if( $status === 'processing' ) {
        //dump("ステータス: processing... 発行を待っています。");
        sleep( 1 );
        $call_on_wait && call_user_func( $call_on_wait( $orderData ) );
      }
      if( $status === 'valid' ) {
        //dump("証明書が発行されました！");
        break;
      }
      if( time() > $until ) {
        //dump("タイムアップ・中断");
        break;
      }
    } while ( $status === 'processing' || $status === 'pending' );
    
    
    return $orderData->status == 'valid';
    //dump($certificateUrl);
    //return $certificateUrl;
    
  }
  
  public function checkFinalizeResultStatus( AcmeOrder $order ) {
    $req = $order->createFinalizeStatusCheckRequest();
    $cli = new AcmeHTTPClient();
    $res = $cli->send( $req );
    $obj = json_decode( $res->getBody()->getContents() );
    $order->updateStatus( $obj->status );
    if ( property_exists($obj,'certificate')){
      $order->updateOrderProperty( 'certificate', $obj->certificate );
    }
    return $obj;
  }
  
  public function finalize( AcmeAccount $account, AcmeOrder $order, string $csr_pem, ?string $nonce ) {
    $this->nonce = $nonce ? new AcmeNonce( $nonce ) : $this->nonce;
    $req = $order->createFinalizeRequest( $account, $this->nonce, $csr_pem );
    $cli = new AcmeHTTPClient();
    $res = $cli->send( $req );
    $obj = json_decode( $res->getBody()->getContents() );
    return $obj;
  }
  
  public function waitForFinalize( AcmeOrder $order, callable $call_on_wait = null ): bool {
    $max_wait_sec = 30;
    $until = time() + $max_wait_sec;
    do {
      // Order の最新状態を取得
      $orderData = $this->checkFinalizeResultStatus( $order );
      $status = $orderData->status;
      //dump($orderData);
      
      if( $status === 'processing' ) {
        //dump("ステータス: processing... 発行を待っています。");
        sleep( 1 );
        $call_on_wait && call_user_func( $call_on_wait( $orderData ) );
      }
      if( $status === 'valid' ) {
        //dump("証明書が発行されました！");
        break;
      }
      if( time() > $until ) {
        //dump("タイムアップ・中断");
        break;
      }
    } while ( $status === 'processing' || $status === 'pending' );
    
    dump( $order );
    
    return $orderData->status == 'valid';
  }
}