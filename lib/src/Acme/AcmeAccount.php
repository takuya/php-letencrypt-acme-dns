<?php

namespace Takuya\LEClientDNS01\Acme;

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Psr\Http\Message\ResponseInterface;

/**
 * ユーザーデータの保存などを行うと処理が早くなって佳き。
 */
class AcmeAccount {
  /**
   * @param string      $email
   * @param string|null $private_key PEM
   * @param string|null $account_url kid
   */
  public function __construct(
    protected string $email,
    protected ?string $private_key=null,
    protected ?string $account_url=null,
  ) {
    if (empty($private_key)){
      $this->private_key = (new AsymmetricKey())->privKey();
    }
  }
  public function private_key_pem(): string {
    return $this->private_key;
  }
  public function email():string {
    return $this->email;
  }
  public function updateAccountUrl(ResponseInterface $response):string {
    $kid = $response->getHeaderLine('Location');
    $this->account_url = $kid;
    return $kid;
  }
  public function getAccountUrl():string {
    return $this->account_url;
  }
  public function kid():string {
    return $this->getAccountUrl();
  }
  
}