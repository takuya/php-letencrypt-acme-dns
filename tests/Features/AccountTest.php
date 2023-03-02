<?php

use tests\Features\CertTestCase;

class AccountTest extends CertTestCase {
  public function test_save_acme_account(){

    $tmp = tempnam(sys_get_temp_dir(),'sample');
    $cli = $this->getInstanceLetsEncryptAcmeDNS();
    $acc = $cli->getAccount();
    $ret = $acc->save($tmp);
    
    $this->assertTrue($ret);
    $this->assertEquals(json_decode($acc->toJson()),json_decode(file_get_contents($tmp)));
  }
  
}