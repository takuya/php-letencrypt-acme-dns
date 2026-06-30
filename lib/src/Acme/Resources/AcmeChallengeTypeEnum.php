<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

enum AcmeChallengeTypeEnum:string {
  case HTTP01 = "http-01";
  case DNS01= "dns-01";
  case TLS_ALPN_01="tls-alpn-01";
}