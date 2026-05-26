<?php

namespace Takuya\LEClientDNS01\Acme\Resources\Directory;

//
//enum AcmeEndpointEnum :string {
//  case newAccount = AcmeEndpointNewAccount::class;
//  case newNonce = AcmeEndpointNewNonce::class;
//  case newOrder = AcmeEndpointNewOrder::class;
//  case revokeCert = AcmeEndpointRevokeCert::class;
//
//  public function getRequestObjectClass(): string {
//    return match($this){
//      AcmeEndpointEnum::newNonce  => RequestNewNonceDirectoryRequest::class,
//      AcmeEndpointEnum::newAccount=> RegisterNewAccountDirectoryRequest::class,
//      AcmeEndpointEnum::newOrder  => StartNewOrderDirectoryRequest::class
//    };
//  }
//}


enum AcmeEndpointEnum :string{
    case newAccount = AcmeEndpointNewAccount::class;
    case newNonce = AcmeEndpointNewNonce::class;
    case newOrder = AcmeEndpointNewOrder::class;
    case revokeCert = AcmeEndpointRevokeCert::class;
}
