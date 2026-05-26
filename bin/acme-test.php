<?php
require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';

use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Acme\Resources\AcmeDirectory;
use Takuya\LEClientDNS01\Acme\Resources\Directory\AcmeEndpointEnum;
use Takuya\LEClientDNS01\Acme\AcmeClient;
use Takuya\LEClientDNS01\Acme\AcmeAccount;
use Takuya\LEClientDNS01\Acme\Resources\AcmeOrder;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
use function Takuya\Utils\base64_url_encode;
use Takuya\LEClientDNS01\Acme\Requests\AcmeRequest;
use Takuya\LEClientDNS01\PKey\CSRSubject;
use Takuya\LEClientDNS01\PKey\SSLCertificateInfo;


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


$key = new AsymmetricKey(file_get_contents('sample.pkey'));
//// [ACME Step 1] Directory取得: 各機能のURL一覧を取得
$dir = new AcmeDirectory(STAGING);
$url = $dir->getDirectoryUrl(AcmeEndpointEnum::newNonce);

//// [ACME Step 2] Initial Nonce取得: 署名に必要な使い捨てトークンを取得
$cli = new AcmeClient($dir);
$nonce = $cli->newNonce();


dump($nonce);

//// [ACME Step 3] newAccount: 公開鍵を登録してアカウントを作成(JWK署名)
$account =new AcmeAccount("admin@{$sub_domain}",$key->privKey());
$ret = $cli->newAccount($account,$nonce);

$new_order = $cli->newOrder($account,[$sub_domain]);
$authorization =$new_order->getAuthorization($sub_domain);
$challenge = $authorization->getChallenge();
//dump($challenge);
////// [ACME Step 6] DNSレコード設置: TXTレコードを設定し反映を待機
$jwt = AcmeRequest::jwt($account->private_key_pem());
$dns = new CloudflareDNSPlugin( $cf_api_token, $base_domain );
dump('_acme-challenge.'.$sub_domain);
$dns->enable_dns_check_at_waiting_for_update = true;
$thumbprint = base64_url_encode(hash('sha256', json_encode($jwt), true));
$keyAuthorization = $challenge->getAuthToken() . '.' . $thumbprint;
$dnsValue = base64_url_encode(hash('sha256', $keyAuthorization, true));
$dns->addDnsTxtRecord('_acme-challenge.'.$sub_domain,$dnsValue);
$dns->waitForUpdated('_acme-challenge.'.$sub_domain,'TXT',$dnsValue, fn()=>dump('waiting..'));
////
//
['response'=>$ret,'nonce'=>$nonce]=$cli->challengeAuthorization($challenge,$account,$nonce);
$ret = $cli->waitForAuthorization($challenge);



// finalize

$dn = new CSRSubject( ...[
  'commonName'              => $sub_domain,
  'subjectAlternativeNames' => [$sub_domain],
  'countryName'             => 'JP',
  'stateOrProvinceName'     => 'Osaka',
] );
$domain_pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
$csrPem = $dn->getRequest( $domain_pkey );

$ret = $cli->finalize($account,$new_order,$csrPem,$nonce);
dump(['finalize'=>$ret]);
$cli->waitForFinalize($new_order);
$certificateUrl = $new_order->getCertificateUrl(); // これがダウンロードURL
$cert = file_get_contents($certificateUrl);
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

//dump($ret, $new_order);
//// [ACME Step 9] finalize: CSRを送信して注文を確定させる
//
//$dn = new CSRSubject( ...[
//  'commonName' => $sub_domain,
//  'subjectAlternativeNames' => [$sub_domain],
//  'countryName'=>'JP',
//  'stateOrProvinceName'=>'Osaka',
//] );
//$domain_pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
//$csrPem = $dn->getRequest($domain_pkey);
//// 2. PEMからヘッダー/フッター、改行を除去してバイナリに戻す
//// 正規表現で ---BEGIN--- と ---END--- の間のベース64部分だけを抜く
//$innerBase64 = preg_replace('/\-+BEGIN CERTIFICATE REQUEST\-+/', '', $csrPem);
//$innerBase64 = preg_replace('/\-+END CERTIFICATE REQUEST\-+/', '', $innerBase64);
//$innerBase64 = trim($innerBase64);
//
//// 3. 一旦バイナリ(DER)にデコード
//$csrDer = base64_decode($innerBase64);
//
//// 4. それを再度「Base64URL」形式でエンコード（パディング無し）
//$csrBase64Url = base64_url_encode($csrDer);
//
//// 5. ペイロード作成
//$payload = ["csr" => $csrBase64Url];
//$protected = [
//  "alg"   => "RS256",
//  "kid"   => $kid, // アカウントURL
//  "nonce" => $nonce,
//  "url"   => $orderData->finalize, // dns-01 オブジェクトの中の "url"
//];
//$payloadStr = base64_url_encode(json_encode($payload));
//$protectedStr = base64_url_encode(json_encode($protected));
//$signingInput = $protectedStr . '.' . $payloadStr;
//openssl_sign($signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256);
//$signatureStr = base64_url_encode($signature);
////// 6. 最終的な JSON ボディ
//$body = json_encode([
//  "protected" => $protectedStr,
//  "payload"   => $payloadStr,
//  "signature" => $signatureStr,
//]);
//
//$res = $cli->request('POST', $orderData->finalize, [
//  'headers' => ['Content-Type' => 'application/jose+json'],
//  'body' => $body
//]);
//
//
//// [ACME Step 10] Orderポーリング: 注文ステータスが valid になる(発行)まで待機
//do {
//  // Order の最新状態を取得
//  $res = $cli->request('GET', $orderURL); // newOrder した時の Location
//  $orderData = json_decode($res->getBody());
//  $status = $orderData->status;
//
//  if ($status === 'processing') {
//    dump("ステータス: processing... 発行を待っています。");
//    sleep(2);
//  }
//} while ($status === 'processing');
//
//if ($status === 'valid') {
//  dump("証明書が発行されました！");
//  $certificateUrl = $orderData->certificate; // これがダウンロードURL
//}
//
//dump($certificateUrl);
//// [ACME Step 11] 証明書取得: certificate URLからPEMをダウンロード
//$res = $cli->request('GET', $certificateUrl);
//$cert = $res->getBody()->getContents();
//dump(new SSLCertificateInfo($cert));
//
//dump(
//  [
//    'cert'=>[
//      'domain_priv_key'=> $domain_pkey,
//      'domain_certificate'=>$cert
//    ],
//    'account'=>[
//      'account_private_key'=> $account_pkey,
//      'account_url(kid)' => $kid
//    ]
//  ]
//);
