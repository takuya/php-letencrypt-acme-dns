<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Takuya\LEClientDNS01\Acme\Requests\AcmeRequest;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * GuzzleHTTP wrapper
 * Nonce の管理とか JWT の管理を行う。はずだったけど、辞めた。
 * Requestオブジェクトの方でACME実装を受け持つことにした。
 *
 */
class AcmeHttpClient {
  
  protected static \GuzzleHttp\Client $cli;
  public static RequestInterface $lastRequest;
  public static ResponseInterface $lastResponse;
  
  
  public static function send( AcmeRequest $r): \Psr\Http\Message\ResponseInterface {
    if (!isset(static::$cli)){
      static::$cli = new \GuzzleHttp\Client();
    }
    static::$lastRequest = new \GuzzleHttp\Psr7\Request( $r->getMethod(), $r->getRequestUrl(), $r->getHeaders(), $r->getBody() );
    try {
      return static::$lastResponse= static::$cli->send( static::$lastRequest );
    } catch (\GuzzleHttp\Exception\ClientException $e) {
      throw new AcmeHttpException($e->getRequest(),$e->getResponse(),$e->getPrevious());
    }
  }
}