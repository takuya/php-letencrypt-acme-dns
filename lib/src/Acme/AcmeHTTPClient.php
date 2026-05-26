<?php

namespace Takuya\LEClientDNS01\Acme;

use GuzzleHttp\Psr7\Request;
use Takuya\LEClientDNS01\Acme\Requests\AcmeRequest;

/**
 * Nounce の管理とか JWT の管理を行う。はずだったけど、辞めた。
 *
 */
class AcmeHTTPClient {
  
  protected \GuzzleHttp\Client $cli;
  
  public function __construct() {
    $this->cli = new \GuzzleHttp\Client();
  }
  public function send( AcmeRequest $r) {
    $req = new Request( $r->getMethod(), $r->getRequestUrl(), $r->getHeaders(), $r->getBody() );
    try {
      $res = $this->cli->send( $req );
      return $res;
    } catch (\GuzzleHttp\Exception\ClientException $e) {
      dd( ['acme_req'=>$r,'http_req'=>$req,'url'=>(string)$req->getUri(),'body'=>$e->getResponse()->getBody()->getContents()] );
    }
  }
  public function get($url) {
    return $this->cli->get($url);
  }
}