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

### EXAMPLE
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
$cli = new LetsEncryptAcmeDNS( $owner_pkey, $your_email );
$cli->setDomainNames( $domain_names );
$cli->setAcmeURL( LetsEncryptACMEServer::PROD );
$cli->setDnsPlugin( $dns );
$cert_and_a_key = $cli->orderNewCert();

/** ********
 * Save in your own way.
 */
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


### Example Two of DNS server 
If you uses two dns server , you can set dns per domain.

For example , to issie two domain in SAN.

| cert | domain                                   |
|---|------------------------------------------|
|commonName| example.tld                              | 
|subjectAltName| DNS:example.**tld**, DNS:example.**biz** |

DNS-01 plugins above example.

| Base Domain     | Plugin           |API Key |
|-----------------|------------------|---|
| example.**tld** | cloudflare       | cloudflare_token |
| example.**biz** | your_own_plugnin | your_own_key |

You can use Multiple Domain update API to complete Let's Encrypt ACME challenge.

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
    "pear/net_dns2": "^1.5",
    "ext-openssl": "*"
```
Fiber used. To use Fiber php8.1 required. Fiber used in waiting dns update.
## Requirements
To Check DNS TXT recoed updated.
- This package requires `Outbound UDP/53 are opened`.

## Future Plan

I will remove `acme/php` dependency in the future.






