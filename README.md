## LetsEncrypt for DNS-01 and Cloudflare

This Library helps us to obtain Let's Encrypt SSLCertificate with DNS-01 ACMEv2.

This is **Pure-PHP** , For embedded to WEB PHP-App (ex. laravel). 

**Independent** from `shell command` like `certbot`.   

### Run ACME. 
request issue of certificate by DNS-01.
```php
export LE_CLOUDFLARE_TOKEN='X-811Gxxxxx'
export LE_EMAIL='yourname@example.tld'
bin/request-issue 'aab.example.tld' 'aaa.example.tld'
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
/** ********
 * Order certificate.
 */
$dns = new CloudflareDNSRecord( $cf_api_token, base_domain($domain_names[0]) );
$cli = new LetsEncryptAcmeDNS( $owner_pkey, $your_email, $domain_names, $dns );
$cert_and_a_key = $cli->orderNewCert(LetsEncryptServer::STAGING);

/** ********
 * Save in your own way.
 */
$cert_pem  = $cert_and_a_key->toArray()['certificate'];
$cert_pkey = $cert_and_a_key->toArray()['private_key'];//domain pkey, not an owner's key.
$full_chain = implode(PHP_EOL,[$cert_pem, ...$cert_and_a_key->toArray()['intermediates']]);
$cert_info = new SSLCertificateInfo( $cert_pem );
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
- This package uses `dig` command, dig need to be installed for DNS SOA/NS/TXT.

## Future Plan

I will remove `acme/php` and `dig` dependency in the near future.






