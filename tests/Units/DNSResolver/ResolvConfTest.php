<?php

namespace DNSResolver;

use tests\TestCase;
use function Takuya\Utils\resolve_conf;
use Takuya\LEClientDNS01\DnsCheck\ResolveConf;

class ResolvConfTest extends TestCase {
  protected string $path;
  
  protected function setUp(): void {
    parent::setUp();
    ResolveConf::$path = $this->path = $this->getTempFilePath();
    register_shutdown_function(fn()=> file_exists($this->path) && unlink($this->path) );
  }
  protected function getTempFilePath() {
    $a = tmpfile();
    $path = stream_get_meta_data($a)['uri'];
    fclose($a);
    return $path;
  }
  
  
  public function test_get_local_dns_resolveconf() {
    file_put_contents($this->path,<<<"EOS"
    ##
    nameserver   1.1.1.1
    nameserver 1.0.0.1
    search aa
    EOS
    );
    $ret = resolve_conf();
    $this->assertEquals(['1.1.1.1','1.0.0.1'], $ret['nameserver']);
    $this->assertEquals(['aa'], $ret['search']);
  }
  
}