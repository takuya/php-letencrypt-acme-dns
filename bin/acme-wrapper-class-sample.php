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
use Takuya\LEClientDNS01\Delegators\AcmePHPWrapper;
use Takuya\LEClientDNS01\Account;


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
$cli = new AcmePHPWrapper(STAGING);
//// [ACME Step 2] Initial Nonce取得: 署名に必要な使い捨てトークンを取得
$account = Account::create("admin@{$sub_domain}");
$cli->newAccount($account);
$cli->newOrder([$sub_domain]);
$challenges = $cli->getDnsChallenge();
$dns = new CloudflareDNSPlugin( $cf_api_token, $base_domain );
$dns->enable_dns_check_at_waiting_for_update = true;
foreach ( $challenges as $challenge ) {
  $v = ['_acme-challenge.'.$challenge->getDomainName(),$challenge->getDnsValue()];
  $dns->addDnsTxtRecord(...$v);
  $dns->waitForUpdated($v[0],'TXT',$v[1], fn()=>dump('waiting..'));
  $cli->challengeAuthorization($challenge->getDomainName());
}
////
//
$dn = $cli->createCSRSubject();
$domain_pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
$cli->finalizeOrderCertificate($dn->opensslCsr( $domain_pkey ));
$cert = $cli->certificateLastIssued();
dump(new SSLCertificateInfo($cert['cert']));
dump(
  [
    'cert'=>[
      'domain_priv_key'=> $domain_pkey,
      'domain_certificate'=>$cli->certificateLastIssued()
    ],
    //'account'=>[
    //  'account_private_key'=> $account->private_key_pem(),
    //  'account_url(kid)' => $account->kid()
    //]
  ]
);

