<?php

namespace Ns147\SodiumAuth\Test\Middleware;

use Error;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Ns147\SodiumAuth\Middleware\SharedDecryptRequest;
use Ns147\SodiumAuth\Test\Middleware\TestCase;
use ParagonIE\Sapient\CryptographyKeys\SharedEncryptionKey;
use ParagonIE\Sapient\Simple;

final class SharedDecryptRequestTest extends TestCase
{
    public function testGoodKey()
    {
        $key = new SharedEncryptionKey(random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES));

        $middleware = new SharedDecryptRequest($key);

        $decrypted = 'foo=1&joy=2&test=bar';
        $request = Request::create('/foo', 'POST', [], [], [], [], Simple::encrypt($decrypted, $key));

        $response = $middleware->handle($request, function (Request $request) {
            return new Response($request->getContent());
        });

        static::assertEquals($decrypted, $response->getContent());

        $boundRequest = app('request');

        static::assertEquals('1', $boundRequest->input('foo'));
        static::assertEquals('2', $boundRequest->input('joy'));
        static::assertEquals('bar', $boundRequest->input('test'));
    }

    public function testBadKey()
    {
        $key = new SharedEncryptionKey(random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES));
        $badKey = new SharedEncryptionKey(random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_KEYBYTES));

        $middleware = new SharedDecryptRequest($key);

        $decrypted = 'foo=1&joy=2&test=bar';
        $request = Request::create('/foo', 'POST', [], [], [], [], Simple::encrypt($decrypted, $badKey));

        static::expectException(Error::class);

        $middleware->handle($request, function (Request $request) {
            return new Response($request->getContent());
        });
    }
}
