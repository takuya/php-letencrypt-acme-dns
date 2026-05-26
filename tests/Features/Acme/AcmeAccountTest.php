<?php

namespace tests\Units\Acme;

use tests\TestCase;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\AcmeClient;

class AcmeAccountTest extends TestCase {
  public function test_create_acme_account() {
    $pkey = new AsymmetricKey();
    $email = sprintf("admin-%s@example.tld", RandomString::gen(10,RandomString::LOWER));
    $account = new AcmeAccount($email, $pkey->privKey());
    $STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    
    $dir = new AcmeDirectory($STAGING);
    $dir->getDirectoryUrl(AcmeEndpointEnum::newNonce);
    $cli = new AcmeClient($dir);
    $nonce = $cli->newNonce();
    $ret = $cli->newAccount($account,$nonce);
    dump($ret);
  }
}