<?php

namespace Ns147\SodiumAuth\Providers\Paseteo;

use Carbon\Carbon;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Protocol\Version2;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Rules\{
    IdentifiedBy,
    NotExpired,
    Subject
};
use ParagonIE\Paseto\JsonToken;
use Symfony\Component\HttpFoundation\Cookie;
use Illuminate\Contracts\Encryption\Encrypter;
use Illuminate\Contracts\Config\Repository as Config;
use Ns147\SodiumAuth\Contracts\Providers\Token;
use Ns147\SodiumAuth\Support\Utils;
use Ns147\SodiumAuth\Exceptions\TokenInvalidException;
use Ns147\SodiumAuth\Exceptions\TokenException;

class ApiTokenFactory implements Token
{
    /**
     * The TTL.
     *
     * @var int
     */
    protected $ttl;

    /**
     * The Parser instance.
     *
     * @var \ParagonIE\Paseto\Parser
     */
    protected $parser;

    /**
     * The secret.
     *
     * @var string  $secret
    */
    protected $secret;

    /**
     * The subject.
     *
     * @var string  $subject
    */
    protected $subject;

    /**
     * The issuedBy.
     *
     * @var string  $issuedBy
    */
    protected $issuedBy;

    /**
     * Create the Paseto provider.
     * @param  string  $secret
     * @param  string  $subject
     * @param  string  $issuedBy
     * @param  int  $ttl
     *
     * @return void
     */
    public function __construct($secret, $issuedBy, $subject, $ttl = 60)
    {
        $this->secret = $secret;
        $this->issuedBy = $issuedBy;
        $this->subject = $subject;
        $this->ttl = $ttl;
        $this->parser = $this->setParser();
    }

    /**
     * Paseto token parser instance.
     *
     * @return \ParagonIE\Paseto\Parser
     */
    protected function setParser()
    {
        $private = AsymmetricSecretKey::fromEncodedString($secret);
        return new Parser(
            ProtocolCollection::v2(),
            Purpose::public(),
            $private->getPublicKey(),
            [new IdentifiedBy($issuedBy), new Subject($subject)]
        );
    }

    /**
     * Create a Paseto Token.
     *
     * @param  array  $payload
     *
     * @throws Exception
     *
     * @return string
     */
    public function encode(array $payload)
    {
        try {
            $private = AsymmetricSecretKey::fromEncodedString($secret);

            $token = (new Builder())
                ->setKey($private)
                ->setJti($issuedBy)
                ->setSubject($subject)
                ->setVersion(new Version2())
                ->setIssuedAt(Utils::now())
                ->setPurpose(Purpose::public())
                ->setExpiration(Utils::now()->addMinutes($this->ttl))
                ->setClaims($payload);
        } catch (Exception $e) {
            throw new TokenException('Could not create token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return $token->toString();
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param  string  $token
     *
     * @throws \ Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return array
    */
    public function decode($token)
    {
        try {
            $jsonToken = $parser->parse($token);
        } catch (PasetoException $ex) {
            throw new TokenInvalidException('Could not decode token: '.$e->getMessage(), $e->getCode(), $e);
        }

        return (new Collection($jsonToken->getClaims()))->map(function ($claim) {
            return is_object($claim) ? $claim->getValue() : $claim;
        })->toArray();
    }
}