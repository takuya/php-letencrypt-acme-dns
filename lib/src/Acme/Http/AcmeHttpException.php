<?php

namespace Takuya\LEClientDNS01\Acme\Http;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class AcmeHttpException extends \RuntimeException {
  public function __construct(
    protected RequestInterface  $request,
    protected ResponseInterface $response,
    ?\Throwable                 $previous = null,
  ) {
    $body = $response->getBody()->getContents();
    $error_body = json_decode( $body );
    parent::__construct( sprintf(
      "Acme Error(%s) %s->%s", $error_body->status, $error_body->type, $error_body->detail ),
      $error_body->status,
      $previous );
  }
}