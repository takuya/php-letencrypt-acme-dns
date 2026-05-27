<?php

namespace tests\Features\Acme;

use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectoryEnum;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use Takuya\LEClientDNS01\Acme\Http\AcmeHttpException;

class AcmeAccountTest extends AcmeTestCase {
  public function test_create_acme_account() {
    //
    try {
      $str = RandomString::gen( 5, RandomString::LOWER );
      $domain_name = "phpunit-{$str}.{$this->base_domain}";
      $pkey = new AsymmetricKey();
      $email = sprintf( "admin-%s@%s", RandomString::gen( 10, RandomString::LOWER ), $domain_name );
      
      //
      $dir = new AcmeDirectory( LetsEncryptACMEServer::STAGING );
      $dir->getDirectoryUrl( AcmeDirectoryEnum::newNonce );
      $cli = new AcmeClient( $dir );
      $nonce = $cli->newNonce();
      $account = new AcmeAccount( $email, $pkey->privKey() );
      $cli->newAccount( $account, $nonce );
      $this->expectNotToPerformAssertions();
    }catch (\Exception $e){
      throw $e;
    }
  }
  
  public function test_create_invalid_acme_account() {
    $this->expectException( AcmeHttpException::class );
    //
    $str = RandomString::gen( 5, RandomString::LOWER );
    $domain_name = "phpunit-{$str}.{$this->base_domain}";
    $pkey = new AsymmetricKey();
    $email = sprintf( "admin-%s@%s.example.tld", RandomString::gen( 10, RandomString::LOWER ), $domain_name );
    
    //
    $dir = new AcmeDirectory( LetsEncryptACMEServer::STAGING );
    $dir->getDirectoryUrl( AcmeDirectoryEnum::newNonce );
    $cli = new AcmeClient( $dir );
    $nonce = $cli->newNonce();
    $account = new AcmeAccount( $email, $pkey->privKey() );
    $cli->newAccount( $account, $nonce );
  }
}