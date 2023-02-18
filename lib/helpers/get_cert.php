<?php


if ( !function_exists( 'get_certificate' ) ) {
  function get_certificate ( $domain, $port = 443 ): string {
    if ( empty( $domain ) ) {
      throw new RuntimeException( 'domain name args ($domain) required' );
    }
    $addr = "tls://${domain}:${port}";
    $ctx = stream_context_create( [
      'ssl' => [
        'verify_peer_name' => false,
        'verify_peer' => false,
        'capture_peer_cert' => true,
      ],
    ] );
    $fp = stream_socket_client(
      $addr, $errno, $err_msg, 5, STREAM_CLIENT_CONNECT, $ctx );
    $result = stream_context_get_params( $fp );
    /** @var OpenSSLCertificate $cert */
    $cert =  $result['options']['ssl']['peer_certificate'];
    openssl_x509_export($cert,$pem);
    return $pem;
  }
}
