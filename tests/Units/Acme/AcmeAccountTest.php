<?php

namespace tests\Units\Acme;

use tests\TestCase;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;

class AcmeAccountTest extends TestCase {
  public function test_create_acme_account() {
    //$pkey = new AsymmetricKey();
    //$email = sprintf("admin-%s@example.tld", RandomString::gen(10,RandomString::LOWER));
    //$acct = new AcmeAccount($email, $pkey->privKey());
    $STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
    
    $dir = new AcmeDirectory($STAGING);
    $res = $dir->getResource(AcmeEndpointEnum::newAccount);
    dd($res);
  }
}