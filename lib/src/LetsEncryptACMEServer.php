<?php

namespace Takuya\LEClientDNS01;

enum LetsEncryptACMEServer {
  const STAGING = 'https://acme-staging-v02.api.letsencrypt.org/directory';
  const PROD = 'https://acme-v02.api.letsencrypt.org/directory';
  
}