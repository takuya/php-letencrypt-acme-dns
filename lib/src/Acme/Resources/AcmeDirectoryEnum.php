<?php

namespace Takuya\LEClientDNS01\Acme\Resources;


enum AcmeDirectoryEnum {
  case newAccount;
  case newNonce;
  case newOrder;
  case revokeCert;
}
