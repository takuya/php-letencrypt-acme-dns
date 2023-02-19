<?php

namespace tests\Features\DNS;

use tests\Features\CertTestCase;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\RandomString\RandomString;

class CloudflarePluginTest extends CertTestCase {
  
  public function test_add_remove_txt_record(){
    $pair1 =[$this->base_domain1, $this->cf_api_token1];
    $pair2 =[$this->base_domain2, $this->cf_api_token2];
    //dump([$pair1,$pair2]);
    [$base_domain,$token] = $pair1;
    $cf = new CloudflareDNSPlugin($token,$base_domain);
    //
    [$name,$content] = [
      sprintf("%s.php-le-test.{$base_domain}",RandomString::gen( 5, RandomString::LOWER )),
      sprintf("sample-api-%s",RandomString::gen( 15, RandomString::ALPHA ))
    ];
    // add.
    $cf->addDnsTxtRecord($name,$content);
    $cf->waitForUpdated($name,'txt',$content);
    $this->assertEquals($content,$cf->query($name,'txt'));
    // remove.
    $cf->removeTxtRecord($name,$content);
  }
}