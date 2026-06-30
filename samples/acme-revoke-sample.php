<?php

require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

use Takuya\LEClientDNS01\Acme\X509SSLCertificate;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectoryEnum;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Http\AcmeNonce;
use Takuya\LEClientDNS01\Acme\Resources\AcmeRevokeCertReason;

const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';



$obj = json_decode(file_get_contents('sample-cert.json'));
$cert =  new X509SSLCertificate($obj->certificate);
$a = json_decode(file_get_contents('sample-account.json'));
$account = new AcmeAccount($a->email,$a->pkey,$a->kid);
//$dir = new AcmeDirectory(STAGING);
$cli = new AcmeClient( $dir = new AcmeDirectory(STAGING));
$res = $cli->renewalInfo($obj->certificate);
$nonce = $cli->newNonce();
$res = $cli->revokeCert($account, $cert->fullChainCerts()[0]);
dd($res);

