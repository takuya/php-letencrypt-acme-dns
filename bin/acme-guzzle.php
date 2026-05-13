<?php
require_once __DIR__.DIRECTORY_SEPARATOR.'../vendor/autoload.php';
use GuzzleHttp\Client;
use Takuya\LEClientDNS01\PKey\AsymmetricKey;
use function Takuya\Utils\base64_url_encode;
use Takuya\RandomString\RandomString;
use Takuya\LEClientDNS01\Plugin\DNS\CloudflareDNSPlugin;
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


///
// [ACME Step 1] Directory取得: 各機能のURL一覧を取得
$cli = new Client();
$res = $cli->request('GET' , STAGING);
$dir = json_decode($res->getBody()->getContents());
//dd($dir->newAccount,$dir->newNonce);
//

// [ACME Step 2] Initial Nonce取得: 署名に必要な使い捨てトークンを取得
$res = $cli->request('GET' , $dir->newNonce);
$nonce = $res->getHeaderLine('Replay-Nonce');

// [ACME Step 3] newAccount: 公開鍵を登録してアカウントを作成(JWK署名)
$pkey = new AsymmetricKey();
/** @var OpenSSLAsymmetricKey $key */
$ret =openssl_pkey_get_details($openSSL_asymmetric_key=openssl_pkey_get_private($pkey->privKey()));
$jwt= [
  // 順番は重要
  'e' => base64_url_encode($ret['rsa']['e']),
  'kty' => 'RSA',
  'n' => base64_url_encode($ret['rsa']['n']),
];
$protected = [
  "alg" => "RS256",
  "jwk" => $jwt,
  "nonce" => $nonce, // 取得済みの Nonce
  "url"   => $dir->newAccount, // Directoryから取得したURL
];
$payload = [
  "termsOfServiceAgreed" => true,
  "contact" => ["mailto:acme@{$base_domain}"],
];

$payloadStr = base64_url_encode(json_encode($payload));
$protectedStr = base64_url_encode(json_encode($protected));
$signingInput = $protectedStr . '.' . $payloadStr;
openssl_sign($signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256);
$signatureStr = base64_url_encode($signature);
// 6. 最終的な JSON ボディ
$body = json_encode([
  "protected" => $protectedStr,
  "payload"   => $payloadStr,
  "signature" => $signatureStr,
]);

$res = $cli->request('POST',$dir->newAccount,[
  'headers'=>[
    'Content-Type'  => 'application/jose+json',
    'Accept'  => 'application/jose+json',
  ],
  'body'=> $body,
]);

//dump( json_decode($res->getBody()->getContents())?->status =='valid' );
$kid = $res->getHeaderLine("Location");
$nonce = $res->getHeaderLine("Replay-Nonce");
/////////////////////////////////////////////////////////////////////////////////
// [ACME Step 4] newOrder: 証明書を発行するドメインを申請(以降KID署名)
/////////////////////////////////////////////////////////////////////////////////
$protected = [
  "alg"   => "RS256",
  "kid"   => $kid, // newAccountのLocationで得たURL
  "nonce" => $nonce, // newAccountのレスポンスヘッダから取得
  "url"   => $dir->newOrder,
];

$payload = [
  "identifiers" => [
    ["type" => "dns", "value" => $sub_domain],
  ],
];
$payloadStr = base64_url_encode(json_encode($payload));
$protectedStr = base64_url_encode(json_encode($protected));
$signingInput = $protectedStr . '.' . $payloadStr;
openssl_sign($signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256);
$signatureStr = base64_url_encode($signature);
// 6. 最終的な JSON ボディ
$body = json_encode([
  "protected" => $protectedStr,
  "payload"   => $payloadStr,
  "signature" => $signatureStr,
]);

$res = $cli->request('POST',$dir->newOrder,[
  'headers'=>[
    'Content-Type'  => 'application/jose+json',
    'Accept'  => 'application/jose+json',
  ],
  'body'=> $body,
]);

//dump($res);
$orderData = json_decode($res->getBody()->getContents());
$orderURL = $res->getHeaderLine("Location");
//($orderData);
$authUrl = $orderData->authorizations[0];
$nonce = $res->getHeaderLine("Replay-Nonce");// 次のりえクエストにつなげる


// [ACME Step 5] Authorization/Challenge取得: 検証方法(dns-01)のURLを確認
$res = $cli->request('GET', $authUrl);
$authDetails = json_decode($res->getBody()->getContents());
$challenge = array_find($authDetails->challenges,fn($challenge)=>$challenge->type == 'dns-01');
//var_dump($challenge);

//
//
// [ACME Step 6] DNSレコード設置: TXTレコードを設定し反映を待機
//

$dns = new CloudflareDNSPlugin( $cf_api_token, $base_domain );
dump('_acme-challenge.'.$sub_domain);
$dns->enable_dns_check_at_waiting_for_update = true;
$thumbprint = base64_url_encode(hash('sha256', json_encode($jwt), true));
$keyAuthorization = $challenge->token . '.' . $thumbprint;
$dnsValue = base64_url_encode(hash('sha256', $keyAuthorization, true));
$dns->addDnsTxtRecord('_acme-challenge.'.$sub_domain,$dnsValue);
$dns->waitForUpdated('_acme-challenge.'.$sub_domain,'TXT',$dnsValue, fn()=>dump('waiting..'));


//
// [ACME Step 7] Challenge応答: サーバーに「レコード設置完了」を通知
//

$protected = [
  "alg"   => "RS256",
  "kid"   => $kid, // アカウントURL
  "nonce" => $nonce,
  "url"   => $challenge->url, // dns-01 オブジェクトの中の "url"
];
$payload = (object)[];
$payloadStr = base64_url_encode(json_encode($payload));
$protectedStr = base64_url_encode(json_encode($protected));
$signingInput = $protectedStr . '.' . $payloadStr;
openssl_sign($signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256);
$signatureStr = base64_url_encode($signature);
//// 6. 最終的な JSON ボディ
$body = json_encode([
  "protected" => $protectedStr,
  "payload"   => $payloadStr,
  "signature" => $signatureStr,
]);
$res = $cli->request('POST', $challenge->url, [
  'headers' => ['Content-Type' => 'application/jose+json'],
  'body' => $body
]);
//dump($res->getBody()->getContents());
$nonce = $res->getHeaderLine('Replay-Nonce');
/////
// [ACME Step 8] Challengeポーリング: 検証ステータスが valid になるまで確認
///
do {
  $res = $cli->request('GET', $challenge->url, [
    'headers' => ['Content-Type' => 'application/jose+json'],
    'body' => $body
  ]);
  $data = json_decode($res->getBody());
  $status = $data->status;
  if ($status === 'pending' || $status === 'processing') {
    dump("Current status: $status. Retrying in 2s...");
    sleep(2);
  }else{
    dump($res->getHeaderLine('Replay-Nonce'));
    //$nonce = $res->getHeaderLine('Replay-Nonce');
    //dump($data);
  }

  
} while ($status === 'pending' || $status === 'processing');

///
///

// [ACME Step 9] finalize: CSRを送信して注文を確定させる

$dn = new CSRSubject( ...[
  'commonName' => $sub_domain,
  'subjectAlternativeNames' => [$sub_domain],
  'countryName'=>'JP',
  'stateOrProvinceName'=>'Osaka',
] );
$domain_pkey = openssl_pkey_new( ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => 4096] );
$csrPem = $dn->getRequest($domain_pkey);
// 2. PEMからヘッダー/フッター、改行を除去してバイナリに戻す
// 正規表現で ---BEGIN--- と ---END--- の間のベース64部分だけを抜く
$innerBase64 = preg_replace('/\-+BEGIN CERTIFICATE REQUEST\-+/', '', $csrPem);
$innerBase64 = preg_replace('/\-+END CERTIFICATE REQUEST\-+/', '', $innerBase64);
$innerBase64 = trim($innerBase64);

// 3. 一旦バイナリ(DER)にデコード
$csrDer = base64_decode($innerBase64);

// 4. それを再度「Base64URL」形式でエンコード（パディング無し）
$csrBase64Url = base64_url_encode($csrDer);

// 5. ペイロード作成
$payload = ["csr" => $csrBase64Url];
$protected = [
  "alg"   => "RS256",
  "kid"   => $kid, // アカウントURL
  "nonce" => $nonce,
  "url"   => $orderData->finalize, // dns-01 オブジェクトの中の "url"
];
$payloadStr = base64_url_encode(json_encode($payload));
$protectedStr = base64_url_encode(json_encode($protected));
$signingInput = $protectedStr . '.' . $payloadStr;
openssl_sign($signingInput, $signature, $openSSL_asymmetric_key, OPENSSL_ALGO_SHA256);
$signatureStr = base64_url_encode($signature);
//// 6. 最終的な JSON ボディ
$body = json_encode([
  "protected" => $protectedStr,
  "payload"   => $payloadStr,
  "signature" => $signatureStr,
]);

$res = $cli->request('POST', $orderData->finalize, [
  'headers' => ['Content-Type' => 'application/jose+json'],
  'body' => $body
]);


// [ACME Step 10] Orderポーリング: 注文ステータスが valid になる(発行)まで待機
do {
  // Order の最新状態を取得
  $res = $cli->request('GET', $orderURL); // newOrder した時の Location
  $orderData = json_decode($res->getBody());
  $status = $orderData->status;
  
  if ($status === 'processing') {
    dump("ステータス: processing... 発行を待っています。");
    sleep(2);
  }
} while ($status === 'processing');

if ($status === 'valid') {
  dump("証明書が発行されました！");
  $certificateUrl = $orderData->certificate; // これがダウンロードURL
}

dump($certificateUrl);
// [ACME Step 11] 証明書取得: certificate URLからPEMをダウンロード
$res = $cli->request('GET', $certificateUrl);
$cert = $res->getBody()->getContents();
dump(new SSLCertificateInfo($cert));