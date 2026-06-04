<?php
require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;

use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use Takuya\LEClientDNS01\Acme\Store\AcmeAccountStore;
use Takuya\LEClientDNS01\Acme\Store\AcmeCertificateStore;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\DNSChallengeTask;


const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';



function load_env() {
$obj = (object)[];
  $env_keys = [
    'base_domain'   => 'LE_BASE_DOMAIN1',
    'cf_api_token'  => 'LE_CLOUDFLARE_TOKEN1',
    //
    'base_domain1'  => 'LE_BASE_DOMAIN1',
    'cf_api_token1' => 'LE_CLOUDFLARE_TOKEN1',
    //
    'base_domain2'  => 'LE_BASE_DOMAIN2',
    'cf_api_token2' => 'LE_CLOUDFLARE_TOKEN2',
    'email'         => 'LE_SAMPLE_EMAIL',
  ];
  foreach ( $env_keys as $name => $env_key ) {
    $obj->{$name} = getenv( $env_key );
  }
  return $obj;
}
if (!function_exists('array_find')){
  function array_find(array$arr, callable $comparator) {
    return array_values(array_filter($arr,$comparator)??[])[0];
  }
}
///
$env = load_env();
$base_domain = $env->base_domain1;
$cf_api_token = $env->cf_api_token1;
$sub_domain = sprintf("guzzle-sample-%s.%s",RandomString::gen(5,RandomString::LOWER),$base_domain);


//$key = new AsymmetricKey(file_get_contents('sample.pkey'));
$key = new AsymmetricKey();
//// [ACME Step 1] Directory取得: 各機能のURL一覧を取得
$dir = new AcmeDirectory(STAGING);
//// [ACME Step 2] Initial Nonce取得: 署名に必要な使い捨てトークンを取得
$cli = new AcmeClient($dir);
$nonce = $cli->newNonce();

dump($nonce);

//// [ACME Step 3] newAccount: 公開鍵を登録してアカウントを作成(JWK署名)
$account =new AcmeAccount("admin@{$sub_domain}",$key->privKey());
$ret = $cli->newAccount($account);
//// [ACME Step 4]
$new_order = $cli->newOrder($account,[$sub_domain]);
$authorization =$new_order->getAuthorization($sub_domain);// ココ、複数形になるかも
// ドメイン名=> プラグインを登録する。DNS01 とは限らないわけで。
$challenge = $authorization->getChallenge(AcmeChallengeTypeEnum::DNS01);
//dump($challenge);
////// [ACME Step 6] DNSレコード設置: TXTレコードを設定し反映を待機
$dns = new CloudflareDNSPlugin( $cf_api_token, $base_domain );
dump('_acme-challenge.'.$sub_domain);
$dns->enable_authoritative_check = true;
$thumbprint = base64_url_encode(hash('sha256', Rs256JwsSigner::JwkString($account->private_key_pem()), true));
$keyAuthorization = $challenge->getAuthToken() . '.' . $thumbprint;
$dnsValue = base64_url_encode(hash('sha256', $keyAuthorization, true));
$dns->addDnsTxtRecord('_acme-challenge.'.$sub_domain,$dnsValue);
$dns->waitForUpdated('_acme-challenge.'.$sub_domain,'TXT',$dnsValue, fn()=>dump('waiting..'));
////
//
$cli->challengeAuthorization($new_order,$sub_domain);

// finalize
$dn = new CSRSubject( ...[
  'commonName'              => $sub_domain,
  'subjectAlternativeNames' => [$sub_domain],
  'countryName'             => 'JP',
  'stateOrProvinceName'     => 'Osaka',
] );
$domain_pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
$csrPem = $dn->getRequest( $domain_pkey );

$ret = $cli->finalize($new_order,$csrPem);
//dump(['finalize'=>$ret]);
$cert = $cli->getCertificate($new_order);
dump(new SSLCertificateInfo($cert));

dump(
  [
    'cert'=>[
      'domain_priv_key'=> $domain_pkey,
      'domain_certificate'=>$cert
    ],
    //'account'=>[
    //  'account_private_key'=> $account->private_key_pem(),
    //  'account_url(kid)' => $account->kid()
    //]
  ]
);

AcmeAccountStore::save('sample-account.json', $account);
openssl_pkey_export( $domain_pkey, $domain_pkey_pem );
AcmeCertificateStore::save('sample-cert.json', new CertificateWithPrivateKey($domain_pkey_pem,$cert));

