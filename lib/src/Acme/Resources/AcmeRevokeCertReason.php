<?php

namespace Takuya\LEClientDNS01\Acme\Resources;

enum AcmeRevokeCertReason: int {
  case unspecified = 0;
  case keyCompromise = 1;
  case superseded = 4;
  case cessationOfOperation = 5;
  
  
}