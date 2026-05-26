<?php

namespace Takuya\LEClientDNS01\Acme;

use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\Acme\Http\AcmeDirectoryClient;
use Takuya\LEClientDNS01\Acme\Http\AcmeOrderClient;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;

/**
 * 全体の流れをここで管理する。
 */
class AcmeClient {
  protected AcmeNonce $nonce;
  protected AcmeDirectoryClient $dir_cli;
  
  public function __construct( protected AcmeDirectory $acmeDirectory ) {
    $this->dir_cli = new AcmeDirectoryClient( $this->acmeDirectory );
  }
  public function getNonce():AcmeNonce {
    return $this->nonce;
  }
  
  public function newNonce(): AcmeNonce {
    return $this->nonce = $this->dir_cli->newNonce();
  }
  
  public function newAccount( AcmeAccount $account ): array {
    return $this->dir_cli->newAccount( $account, $this->nonce );
  }
  
  public function newOrder( AcmeAccount $account, array $domains ): AcmeOrder {
    ['new_order' => $body,
     'order_url' => $order_url,
    ] = $this->dir_cli->newOrder( $account, $domains, $this->nonce );
    $new_order = new AcmeOrder(
      $body->status,
      $body->expires,
      $body->identifiers,
      $body->authorizations,
      $body->finalize,
    );
    $new_order->setOrderUrl( $order_url );
    $new_order->setAccount($account);
    return $new_order;
  }
  
  public function challengeAuthorization( AcmeOrder $order, string $domain, AcmeChallengeTypeEnum $type=AcmeChallengeTypeEnum::DNS01 ): void {
    $cli = new AcmeOrderClient($order, $this->nonce);
    $cli->challengeAuthorization($domain, $type);
    $cli->waitForAuthorization($domain,$type);
  }
  
  public function finalize( AcmeOrder $order, string $csr_pem ): AcmeOrder {
    $cli = new AcmeOrderClient($order,$this->nonce);
    $cli->finalizeOrder($csr_pem);
    return $order;
  }
  
  public function getCertificate(AcmeOrder $order): string {
    if (empty($certificate_url = $order->getCertificateUrl())){
      throw new \RuntimeException('order is not finalized.');
    }
    return file_get_contents($certificate_url);
  }
}