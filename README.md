## LetsEncrypt for DNS-01 and Cloudflare

This Library helps us to obtain Let's Encrypt SSLCertificate with DNS-01 ACMEv2.

This is **Pure-PHP** , For embedded to WEB PHP-App (ex. laravel). 

**Independent** from `shell command` like `certbot`.   

### Run ACME. 
request issue of certificate by DNS-01.
```php
export LE_CLOUDFLARE_TOKEN='X-811Gxxxxx'
export LE_EMAIL='yourname@example.tld'
php bin/request-issue.php 'aab.example.tld' 'aaa.example.tld'
```

### EXAMPLE.
In you php code.
```php
<?php

/** ********
 * Prepare
 */ 
$cf_api_token = getenv( 'LE_CLOUDFLARE_TOKEN' );
$your_email   = getenv( 'LE_EMAIL' );
$domain_names = ["www.your-domain.tld",'*.www.your-domain.tld'];
$owner_pkey   = new AsymmetricKey();// user's pkey, not a domain cert  pkey.
$acme_uri     = LetsEncryptACMEServer::STAGING
/** ********
 * Order certificate.
 */
$dns = new CloudflareDNSRecord( $cf_api_token, base_domain($domain_names[0]) );
$cli = new LetsEncryptAcmeDNS( $owner_pkey, $your_email, $domain_names, $dns, $acme_uri );
$cert_and_a_key = $cli->orderNewCert();

/** ********
 * Save in your own way.
 */
$cert_pem  = $cert_and_a_key->cert();
$cert_pkey = $cert_and_a_key->privKey();//domain pkey, not an owner's key.
$full_chain = $cert_and_a_key->fullChain();
$pkcs12     = $cert_and_a_key->pkcs12('enc pass');
$cert_info = new SSLCertificateInfo( $cert_and_a_key->cert(); );
```

## Installation.

From GitHub.
```bash
composer config repositories.'php-letencrypt-cloudflare-dns' \
vcs https://github.com/takuya/'php-letencrypt-cloudflare-dns'  
composer require takuya/'php-letencrypt-cloudflare-dns':master
composer install
```



## dependencies
```
php: >=8.1
composer:
    "cloudflare/sdk": "^1.3",
    "acmephp/core": "^2.1",
    "ext-openssl": "*"
```
Fiber used. To use Fiber php8.1 required. Fiber used in waiting dns update.
## Requirements
To Check DNS TXT recoed updated.
- This package requires `Outbound UDP/53 are opened`.

## Future Plan

I will remove `acme/php` dependency in the future.






