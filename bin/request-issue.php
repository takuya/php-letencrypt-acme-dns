<?php

use Takuya\LEClientDNS01\Account;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;
use function Takuya\Utils\base_domain;
use function Takuya\Utils\assert_str_is_domain;

require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

function filter_argv ( $list ): array {
  $list = array_unique( $list );
  $args = array_filter( $list, fn( $e ) => assert_str_is_domain( $e ) );
  $opts = array_filter( $list, fn( $e ) => str_contains( $e, '--' ) );
  return ['args' => array_values( $args ), 'opts' => array_values( $opts )];
}

if ( sizeof( filter_argv( $argv )['args'] ) == 0 ) {
  printf( "Usage %s example.tld [...www.example.tld] \n", basename( $argv[0] ) );
  printf( "options :  \n", );
  printf( "     --prod\n", );
  printf( "       use production server \n", );
  printf( "       default is staging.\n", );
  exit( 1 );
}
/* ***********************
 *  main.
 * ************************/
$cf_token = getenv( 'LE_CLOUDFLARE_TOKEN' );
$email = getenv( 'LE_EMAIL' ) ?: '';
$domain_names = filter_argv( $argv )['args'];
$base_domain = getenv( 'LE_BASE_DOMAIN' ) ?: base_domain( $domain_names[0] );
$logger = new class { public function debug ( $mess ): void { file_put_contents( "php://stderr", $mess ); } };
$dns_plugin = new CloudflareDNSPlugin( $cf_token, $base_domain );
$acme_server = LetsEncryptACMEServer::STAGING;
if ( in_array( '--prod', filter_argv( $argv )['opts'] ) ) {
  $acme_server = LetsEncryptACMEServer::PROD;
}
//
$cli = new LetsEncryptAcmeDNS( Account::create($email) );
$cli->setAcmeURL( $acme_server );
$cli->setLogger( $logger );
$cli->setDomainNames( $domain_names );
$cli->setDnsPlugin( $dns_plugin );
//
$cert_and_a_key = $cli->orderNewCert();
$info = new SSLCertificateInfo( $cert_and_a_key->cert() );

printf( "
CN    : %s
SAN   : %s
ID    : %s
FROM  :%s
TO    :%s
#
# -------------- private key --------------
#
%s
#
# -------------- certificate --------------
#
%s
#
# -------------- fullchain --------------
#
%s
",
  $info->subject['commonName'],
  $info->extensions['subjectAltName'],
  $info->serialNumberHex,
  $info->validFrom,
  $info->validTo,
  $cert_and_a_key->privKey(),
  $cert_and_a_key->cert(),
  $cert_and_a_key->fullChain(),
);