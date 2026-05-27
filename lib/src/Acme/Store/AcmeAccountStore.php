<?php

namespace Takuya\LEClientDNS01\Acme\Store;

use Takuya\LEClientDNS01\Acme\AcmeAccount;

class AcmeAccountStore {

  public static function save( string $filename , AcmeAccount $account) {
    return file_put_contents( $filename, json_encode($account->toArray(),JSON_PRETTY_PRINT) );
  }
}