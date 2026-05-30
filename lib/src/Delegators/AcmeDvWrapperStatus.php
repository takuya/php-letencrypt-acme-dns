<?php

namespace Takuya\LEClientDNS01\Delegators;


enum AcmeDvWrapperStatus{
  case INITIALIZED;
  case NEW_NONCE_ISSUED;
  case ACCOUNT_REGISTERED;
  case ORDERED;
  case CHALLENGED;
  case FINALIZED;
}