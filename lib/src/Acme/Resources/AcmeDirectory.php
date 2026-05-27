<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

use Takuya\LEClientDNS01\Acme\Requests\RequestNewNonceDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Requests\RegisterNewAccountDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\StartNewOrderDirectoryRequest;
use Takuya\LEClientDNS01\Acme\Requests\RevokeCertDirectoryRequest;

// ACMEコア（RFC 8555）
// ARI（RFC 8739 / renewalInfo）
class AcmeDirectory {
  protected object $directory;
  
  public function __construct(
    public string $url,
  ) {
  }
  
  public function directory() {
    return $this->directory = $this->directory ?? json_decode( file_get_contents( $this->url ) );
  }
  
  public function getDirectoryUrl( AcmeDirectoryEnum $resourceName ): string {
    return $this->directory()->{$resourceName->name};
  }
  
  public function createNewNonceRequest( ?AcmeNonce $nonce = null ): RequestNewNonceDirectoryRequest {
    $nonce = $nonce ?? new AcmeNonce();
    $url = $this->getDirectoryUrl( AcmeDirectoryEnum::newNonce );
    return new RequestNewNonceDirectoryRequest( $nonce, $url );
  }
  
  public function createNewAccountRequest( AcmeNonce   $nonce,
                                           AcmeAccount $account ): RegisterNewAccountDirectoryRequest {
    $url = $this->getDirectoryUrl( AcmeDirectoryEnum::newAccount );
    return new RegisterNewAccountDirectoryRequest( $nonce, $account, $url, 'POST' );
  }
  
  public function createNewOrderRequest( AcmeNonce $nonce, AcmeAccount $account ): StartNewOrderDirectoryRequest {
    $url = $this->getDirectoryUrl( AcmeDirectoryEnum::newOrder );
    return new StartNewOrderDirectoryRequest( $nonce, $account, $url );
  }
  
  public function createRevokeCertRequest(
    AcmeAccount          $account,
    \OpenSSLCertificate  $cert,
    AcmeNonce            $nonce,
    AcmeRevokeCertReason $reason ): RevokeCertDirectoryRequest {
    $url = $this->getDirectoryUrl( AcmeDirectoryEnum::revokeCert );
    return new RevokeCertDirectoryRequest( $nonce, $account, $cert, $url, $reason );
  }
}