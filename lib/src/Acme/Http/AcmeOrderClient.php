<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\Acme\Resources\AcmeAuthorizationChallenge;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeType;

class AcmeOrderClient {
  public function __construct(
    protected AcmeOrder $order,
    protected AcmeNonce $nonce ) {
  }
  
  public function challengeAuthorization( string $domain, AcmeChallengeType $type ): object {
    $req = $this->getChallenge( $domain, $type )->createRequest( $this->nonce, $this->order->getAccount() );
    $res = AcmeHttpClient::send( $req );
    $this->nonce->updateNonce( $res );
    $obj = json_decode( $res->getBody()->getContents() );
    return $obj;
  }
  
  protected function getChallenge( string $domain, AcmeChallengeType $type ): AcmeAuthorizationChallenge {
    return $this->order
      ->getAuthorization( $domain )
      ->getChallenge( $type );
  }
  
  protected function challengeAuthorizationStatus( AcmeAuthorizationChallenge $challenge ) {
    $req = $challenge->createRequestForCheckPendingResult();
    $res = AcmeHttpClient::send( $req );
    $obj = json_decode( $res->getBody()->getContents() );
    return $obj;
  }
  
  protected function wait_for_valid( callable $request_function, string $valid_string, int $max_wait_sec ) {
    $until = time() + $max_wait_sec;
    do {
      $status = call_user_func( $request_function );
      if( time() > $until ) {
        //dump("タイムアップ・中断");
        throw new \RuntimeException( 'gave up ( waiting a status change).' );
      }
    } while ( $status != $valid_string );
    return $status;
  }
  
  public function waitForAuthorization( string $domain, AcmeChallengeType $type, ?callable $call_on_wait = null,
                                        int    $max_wait_sec = 15 ) {
    $challenge = $this->getChallenge( $domain, $type );
    $valid_str = 'valid';
    $status = $this->wait_for_valid( function() use ( $challenge, $valid_str, $call_on_wait ) {
      $obj = $this->challengeAuthorizationStatus( $challenge );
      if( strcasecmp( $valid_str, $obj->status ) !== 0 ) {
        //dump("ステータス: processing... 発行を待っています。");
        sleep( 1 );
        $call_on_wait && call_user_func( $call_on_wait( $obj ) );
      }
      return $obj->status;
    }, $valid_str, $max_wait_sec );
    return $status;
  }
  
  public function finalizeOrder( string $csr_pem ):AcmeOrder {
    $req = $this->order->createFinalizeRequest( $this->order->getAccount(), $this->nonce, $csr_pem );
    $res = AcmeHttpClient::send( $req );
    $this->waitForFinalize();
    return $this->order;
  }
  
  protected function updateFinalizedOrderStatus() {
    $req = $this->order->createFinalizeStatusCheckRequest();
    $res = AcmeHttpClient::send( $req );
    $obj = json_decode( $res->getBody()->getContents() );
    $this->order->updateStatus( $obj->status );
    if( property_exists( $obj, 'certificate' ) ) {
      $this->order->updateOrderProperty( 'certificate', $obj->certificate );
    }
    return $obj;
  }
  
  protected function waitForFinalize(callable $call_on_wait = null, int $max_wait_sec = 15 ) {
    $valid_str = 'valid';
    $status = $this->wait_for_valid( function() use ( $valid_str, $call_on_wait ) {
      $obj = $this->updateFinalizedOrderStatus();
      if( strcasecmp( $valid_str, $obj->status ) !== 0 ) {
        //dump("ステータス: processing... 発行を待っています。");
        sleep( 1 );
        $call_on_wait && call_user_func( $call_on_wait( $obj ) );
      }
      return $obj->status;
    }, $valid_str, $max_wait_sec );
    return $status;
  }
  
  
}