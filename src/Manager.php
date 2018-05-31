<?php

namespace Ns147\SodiumAuth;

use Ns147\SodiumAuth\Support\RefreshFlow;
use Ns147\SodiumAuth\Support\CustomClaims;
use Ns147\SodiumAuth\Exceptions\TokenException;
use Ns147\SodiumAuth\Exceptions\TokenBlacklistedException;
use Ns147\SodiumAuth\Contracts\Providers\Token as TokenContract;

class Manager
{
    use CustomClaims, RefreshFlow;

    /**
     * The provider.
     *
     * @var \Ns147\SodiumAuth\Contracts\Providers\Token
     */
    protected $provider;

    /**
     * The blacklist.
     *
     * @var \Ns147\SodiumAuth\Blacklist
     */
    protected $blacklist;

    /**
     * the payload factory.
     *
     * @var \Ns147\SodiumAuth\Factory
     */
    protected $payloadFactory;

    /**
     * The blacklist flag.
     *
     * @var bool
     */
    protected $blacklistEnabled = true;

    /**
     * the persistent claims.
     *
     * @var array
     */
    protected $persistentClaims = [];

    /**
     * Constructor.
     *
     * @param  \Ns147\SodiumAuth\Contracts\Providers\Token  $provider
     * @param  \Ns147\SodiumAuth\Blacklist  $blacklist
     * @param  \Ns147\SodiumAuth\Factory  $payloadFactory
     *
     * @return void
     */
    public function __construct(TokenContract $provider, Blacklist $blacklist, Factory $payloadFactory)
    {
        $this->provider = $provider;
        $this->blacklist = $blacklist;
        $this->payloadFactory = $payloadFactory;
    }

    /**
     * Encode a Payload and return the Token.
     *
     * @param  \Ns147\SodiumAuth\Payload  $payload
     *
     * @return \Ns147\SodiumAuth\Token
     */
    public function encode(Payload $payload)
    {
        $token = $this->provider->encode($payload->get());

        return new Token($token);
    }

    /**
     * Decode a Token and return the Payload.
     *
     * @param  \Ns147\SodiumAuth\Token  $token
     * @param  bool  $checkBlacklist
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenBlacklistedException
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function decode(Token $token, $checkBlacklist = true)
    {
        $payloadArray = $this->provider->decode($token->get());

        $payload = $this->payloadFactory
                        ->setRefreshFlow($this->refreshFlow)
                        ->customClaims($payloadArray)
                        ->make();

        if ($checkBlacklist && $this->blacklistEnabled && $this->blacklist->has($payload)) {
            throw new TokenBlacklistedException('The token has been blacklisted');
        }

        return $payload;
    }

    /**
     * Refresh a Token and return a new Token.
     *
     * @param  \Ns147\SodiumAuth\Token  $token
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return \Ns147\SodiumAuth\Token
     */
    public function refresh(Token $token, $forceForever = false, $resetClaims = false)
    {
        $this->setRefreshFlow();

        $claims = $this->buildRefreshClaims($this->decode($token));

        if ($this->blacklistEnabled) {
            // Invalidate old token
            $this->invalidate($token, $forceForever);
        }

        // Return the new token
        return $this->encode(
            $this->payloadFactory->customClaims($claims)->make($resetClaims)
        );
    }

    /**
     * Invalidate a Token by adding it to the blacklist.
     *
     * @param  \Ns147\SodiumAuth\Token  $token
     * @param  bool  $forceForever
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return bool
     */
    public function invalidate(Token $token, $forceForever = false)
    {
        if (! $this->blacklistEnabled) {
            throw new TokenException('You must have the blacklist enabled to invalidate a token.');
        }

        return call_user_func(
            [$this->blacklist, $forceForever ? 'addForever' : 'add'],
            $this->decode($token, false)
        );
    }

    /**
     * Build the claims to go into the refreshed token.
     *
     * @param  \Ns147\SodiumAuth\Payload  $payload
     *
     * @return array
     */
    protected function buildRefreshClaims(Payload $payload)
    {
        // assign the payload values as variables for use later
        extract($payload->toArray());

        // persist the relevant claims
        return array_merge(
            $this->customClaims,
            compact($this->persistentClaims, 'sub', 'iat')
        );
    }

    /**
     * Get the Payload Factory instance.
     *
     * @return \Ns147\SodiumAuth\Factory
     */
    public function getPayloadFactory()
    {
        return $this->payloadFactory;
    }

    /**
     * Get the Token Provider instance.
     *
     * @return \Ns147\SodiumAuth\Contracts\Providers\Token
     */
    public function getTokenProvider()
    {
        return $this->provider;
    }

    /**
     * Get the Blacklist instance.
     *
     * @return \Ns147\SodiumAuth\Blacklist
     */
    public function getBlacklist()
    {
        return $this->blacklist;
    }

    /**
     * Set whether the blacklist is enabled.
     *
     * @param  bool  $enabled
     *
     * @return $this
     */
    public function setBlacklistEnabled($enabled)
    {
        $this->blacklistEnabled = $enabled;

        return $this;
    }

    /**
     * Set the claims to be persisted when refreshing a token.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setPersistentClaims(array $claims)
    {
        $this->persistentClaims = $claims;

        return $this;
    }
}
