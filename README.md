## LetsEncrypt for ACME DNS-01 and Cloudflare or your own
[![phpunit](https://github.com/takuya/php-letencrypt-acme-dns/actions/workflows/actions.yml/badge.svg)](https://github.com/takuya/php-letencrypt-acme-dns/actions/workflows/actions.yml)
[![composer](https://github.com/takuya/php-letencrypt-acme-dns/actions/workflows/composer.yml/badge.svg)](https://github.com/takuya/php-letencrypt-acme-dns/actions/workflows/composer.yml)

This Library helps us to obtain Let's Encrypt SSLCertificate with DNS-01 ACMEv2.

This is **Pure-PHP** , intend to be LE embedded WEB-PHP-App (ex. laravel). 

**Independent** from `shell command` like `certbot`.   

### Run ACME. 
request issue of certificate by DNS-01.

shell
```php
export LE_CLOUDFLARE_TOKEN='X-811Gxxxxx'
export LE_EMAIL='yourname@example.tld'
php bin/request-issue.php 'aab.example.tld' 'aaa.example.tld'
```

### EXAMPLE
In you php code.

```php
<?php

/** ********
 * Prepare
 */ 
use Takuya\LEClientDNS01\Account;
$cf_api_token = getenv( 'LE_CLOUDFLARE_TOKEN' );
$your_email   = getenv( 'LE_EMAIL' );
$domain_names = ["www.your-domain.tld",'*.www.your-domain.tld'];
$account = new Account( $your_email );
/** ********
 * Order certificate.
 */
$dns = new CloudflareDNSPlugin( $cf_api_token, base_domain($domain_names[0]) );
$cli = new LetsEncryptAcmeDNS( $account );
$cli->setDomainNames( $domain_names );
$cli->setAcmeURL( LetsEncryptACMEServer::PROD );
$cli->setDnsPlugin( $dns );
$cert_and_a_key = $cli->orderNewCert();
/** ********
 * Save in your own way.
 */
$owner_pkey = $account->private_key;
$cert_pem  = $cert_and_a_key->cert();
$cert_pkey = $cert_and_a_key->privKey();//domain pkey, not an owner's pkey. 
$full_chain = $cert_and_a_key->fullChain();
$pkcs12     = $cert_and_a_key->pkcs12('enc pass');
$cert_info = new SSLCertificateInfo( $cert_and_a_key->cert(); );
```
### More cases.


#### WildCard name. 
```php
$cli->setDomainNames( ['*.your-domain.tld'] );
```
#### Single name
```php
$cli->setDomainNames( ['www.your-domain.tld'] );
```

#### Multiple sub domain
```php
$cli->setDomainNames( ['www.your-domain.tld','ipsec.your-domain.tld'] );
```

#### Multi , different BASE 
```php
$cli->setDomainNames( ['www.first.tld','www.second.tld'] );
```


### Example Two of Two DNS server 
If you uses two dns server , you can set dns per domain.

For example , Cert with two domain in SAN.

| cert | domain                                   |
|---|------------------------------------------|
|commonName| example.tld                              | 
|subjectAltName| DNS:example.**tld**, DNS:example.**biz** |

DNS-01 plugins for above.

| Base Domain     | DNS        | plugin  | 
|-----------------|------------|---------|
| example.**tld** | cloudflare | CloudflareDNSPlugin|
| example.**biz** | your_own   |YourOwnPlugin|

You can use Multiple Domain DNS Server API to complete LE ACME challenge.

```php
<?php
// set dns plugin per Domain.
$cli = new LetsEncryptAcmeDNS( 'priv_key_pem', 'your_email@gmail.com' );
$dns_plugin_1 = new CloudflareDNSPlugin( 'cloudflare_token', 'example.tld' );
$dns_plugin_2 = new YourOwnPlugin( 'your_own_key', 'example.biz' );
$cli->setDnsPlugin( $dns_plugin_1, 'example.tld' );
$cli->setDnsPlugin( $dns_plugin_2, 'example.biz' );
```
## How to write your Own DNS Plugin. 
Create class and extends `DNSPlugin` class.
```php
class YourOwnPlugin extends DNSPlugin{

}
```
Then, complete implementation by your code to update DNS server.
```php
class YourOwnPlugin extends DNSPlugin{
  public function addDnsTxtRecord ( $domain, $content ): bool;{
    // TODO: write your way to add TXT Record for ACME challenge.
  }
  
  public  function removeTxtRecord ( $domain, $content ): bool{
    // TODO: Write in your way, how to remove TXT Record , after ACME.
  }
}

```


## Installation.

From GitHub.
```bash
repository='php-letencrypt-acme-dns'
composer config repositories.$repository \
vcs https://github.com/takuya/$repository  
composer require takuya/$repository:master
composer install
```

From composer packagist
```bash
composer require takuya/php-letencrypt-acme-dns
```


## dependencies
```
php: >=8.1
composer:
    "cloudflare/sdk": "^1.3",
    "acmephp/core": "^2.1",
    "pear/net_dns2": "^1.5",
    "ext-openssl": "*"
```
Fiber used. To use Fiber php8.1 required. Fiber used in waiting dns update.
## Requirements
To Check DNS TXT recoed updated.
- This package requires `Outbound UDP/53 are open`.

## Future Plan

I will remove `acme/php` dependency in the future.






