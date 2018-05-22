<?php

namespace Ns147\SodiumAuth\Test\Middleware;

use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Tests\TestCase;
use Ns147\SodiumAuth\KeyResolver\StaticResolver;
use Ns147\SodiumAuth\Middleware\SealResponse;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\Sapient\CryptographyKeys\SealingSecretKey;
use ParagonIE\Sapient\Simple;

class SealResponseTest extends TestCase
{
    public function testGoodKey()
    {
        $pair = sodium_crypto_box_keypair();
        $public = Base64UrlSafe::encode(sodium_crypto_box_publickey($pair));
        $private = new SealingSecretKey(sodium_crypto_box_secretkey($pair));

        $middleware = new SealResponse(new StaticResolver($public));

        $request = static::createRequest();
        $unsealed = $request->getContent();

        $response = $middleware->handle($request, function (Request $request) {
            return new Response($request->getContent());
        });

        static::assertEquals($unsealed, Simple::unseal($response->getContent(), $private));
    }
}
