<?php

namespace Ns147\SodiumAuth\Test\Providers\Token;

use Mockery;
use Carbon\Carbon;
use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer\Key;
use InvalidArgumentException;
use Ns147\SodiumAuth\Providers\Token\TokenProvider;
use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\Paseto\Exception\InvalidVersionException;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\Version2\AsymmetricPublicKey;
use ParagonIE\Paseto\Keys\Version2\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\Version2\SymmetricKey;
use ParagonIE\Paseto\Protocol\Version1;
use ParagonIE\Paseto\Protocol\Version2;
use Tests\TestCase;

class TokenProviderTest extends TestCase
{

     /**
     * @var string
     */
    protected $private;

     /**
     * @var string
     */
    protected $public;

    /**
     * @var \Ns147\SodiumAuth\Providers\Token\TokenProvider
     */
    protected $provider;

    protected $testNowTimestamp;

    public function setUp()
    {
        parent::setUp();
        $pair = sodium_crypto_sign_keypair();
        $this->private = Base64UrlSafe::encode(sodium_crypto_sign_secretkey($pair));
        $this->public = Base64UrlSafe::encode(sodium_crypto_sign_publickey($pair));
        Carbon::setTestNow($now = Carbon::now());
        $this->testNowTimestamp = $now->getTimestamp();
    }


    /** @test */
    public function it_should_return_the_token_when_passing_a_valid_payload_to_encode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];

        $token = $this->getProvider($this->private)->encode($payload);
        $this->assertInternalType('string', $token);
        $this->assertSame('v2.public.', Binary::safeSubstr($token, 0, 10));
    }

     /** @test */
    public function it_should_return_the_payload_when_passing_a_valid_token_to_decode()
    {
        $payload = ['sub' => 1, 'exp' => $this->testNowTimestamp + 3600, 'iat' => $this->testNowTimestamp, 'iss' => '/foo'];
        $token = $this->getProvider($this->private)->encode($payload);
        $this->assertSame($payload, $this->getProvider($this->private)->decode($token));
    }

    /**
     * @test
     * @expectedException \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     * @expectedExceptionMessage Could not decode token:
     */
    public function it_should_throw_a_token_invalid_exception_when_the_token_could_not_be_decoded()
    {
        $this->getProvider($this->private)->decode('foo.bar.baz');
    }

    public function getProvider($secret)
    {
        return new TokenProvider($secret, 60);
    }

     /**
     * @covers AsymmetricSecretKey for version 2
     *
     * @throws \Error
     * @throws \Exception
     * @throws \TypeError
     */
    public function testWeirdKeypairs()
    {
        $keypair = sodium_crypto_sign_keypair();
        $privateKey = new AsymmetricSecretKey(sodium_crypto_sign_secretkey($keypair));
        $publicKey = new AsymmetricPublicKey(sodium_crypto_sign_publickey($keypair));
        $seed = Binary::safeSubstr($keypair, 0, 32);
        $privateAlt = new AsymmetricSecretKey($seed);
        $publicKeyAlt = $privateAlt->getPublicKey();
        $this->assertSame(
            Base64UrlSafe::encode($privateAlt->raw()),
            Base64UrlSafe::encode($privateKey->raw())
        );
        $this->assertSame(
            Base64UrlSafe::encode($publicKeyAlt->raw()),
            Base64UrlSafe::encode($publicKey->raw())
        );
    }
}
