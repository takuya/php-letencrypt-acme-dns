<?php
require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\LetsEncryptAcmeDNS;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use function Takuya\Utils\dns_resolve;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;
use Takuya\LEClientDNS01\Acme\Resources\AcmeChallengeTypeEnum;

use Takuya\LEClientDNS01\Acme\Http\Rs256JwsSigner;
use Takuya\LEClientDNS01\Acme\Store\AcmeAccountStore;
use Takuya\LEClientDNS01\Acme\Store\AcmeCertificateStore;
use Takuya\LEClientDNS01\PKey\CertificateWithPrivateKey;
use Takuya\LEClientDNS01\DNSChallengeTask;
use Takuya\LEClientDNS01\Delegators\AcmeDvWrapperStatus;
use Takuya\LEClientDNS01\Account;
use function Takuya\Utils\is_directly_resolve_allowed;

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

$cli=new LetsEncryptAcmeDNS($account = Account::create("admin@{$sub_domain}"));
$dns = new CloudflareDNSPlugin( $cf_api_token, $base_domain );
$cli->setDnsPlugin($dns);
$cli->setAcmeURL(STAGING);
$cli->setDomainNames([$sub_domain]);
$cert = $cli->orderNewCert();

dump(new SSLCertificateInfo($cert->fullChain()));
dump(
  [
    'cert'=>[
      'domain_priv_key'=> $cert->privKey(),
      'domain_certificate'=>$cert->fullChain()
    ],
    //'account'=>[
    //  'account_private_key'=> $account->private_key_pem(),
    //  'account_url(kid)' => $account->kid()
    //]
  ]
);
//
