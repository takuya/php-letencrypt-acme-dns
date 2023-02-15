## LetsEncrypt for DNS-01 and Cloudflare

This Library helps us to obtain Let's Encrypt SSLCertificate with DNS-01 ACMEv2.

This for Embedded WEB PHP App for purpose, avoid independent from `shell` and `certbot`.   

### EXAMPLE.

```php
<?php
// prepare 
$base_domain = getenv( 'LE_SAMPLE_BASE_DOMAIN' );
$cf_api_token = getenv( 'LE_SAMPLE_CLOUDFLARE_TOKEN' );
$yousr_email = getenv( 'LE_SAMPLE_EMAIL' );
$domain_name = "www.yourdomain.tld";
$owner_pkey = new AsymmetricKey();// user's pkey, not a domain cert  pkey.
// order certificate.
$dns = new CloudflareDNSRecord( $cf_api_token, $domain_name );
$cli = new LetsEncryptAcmeDNS( $owner_pkey, $yousr_email, $domain_name, $dns );
$cert = $cli->orderNewCert();

// save it in your own way.
$cert_pem  = $cert->toArray()['certificate'];
$cert_pkey = $cert->toArray()['private_key'];//domain pkey, not an owner's key.
$full_chain = implode(PHP_EOL,[$cert_pem, ...$cert->toArray()['intermediates']]);
$cert_info = new SSLCertificateInfo( $cert_pem );
```

## Installation.

From github.
```bash
composer config repositories.'php-letencrypt-cloudflare-dns' \
vcs https://github.com/takuya/'php-letencrypt-cloudflare-dns'  
composer require takuya/'php-letencrypt-cloudflare-dns':master
composer install
```



## dependencies

`dig` is for check updated, dns record in SOA(or NS).

```
composer:
    "cloudflare/sdk": "^1.3",
    "acmephp/core": "^2.1",
    "ext-openssl": "*"
linux command: 
    dig
```

