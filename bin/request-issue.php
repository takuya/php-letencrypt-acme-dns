<?php

use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\LetsEncryptACMEServer;

require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

$cf_token     = getenv( 'LE_CLOUDFLARE_TOKEN' );
$email        = getenv( 'LE_EMAIL' );
$base_domain  = getenv( 'LE_BASE_DOMAIN' );
$domain_names = array_slice( $argv, 1, );
$ownerPkey = new AsymmetricKey();
$logger       = new class {public function debug ( $mess ) { file_put_contents( "php://stderr", $mess ); }};
$dns_plugin   = new CloudflareDNSPlugin( $cf_token, $base_domain ?: base_domain( $domain_names[0] ) );
//
$cli = new LetsEncryptAcmeDNS( $ownerPkey->privKey(),$email );
$cli->setAcmeURL(LetsEncryptACMEServer::PROD);
$cli->setLogger( $logger );
$cli->setDomainNames($domain_names);
$cli->setDnsPlugin($dns_plugin);
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