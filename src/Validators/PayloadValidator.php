<?php

namespace Ns147\SodiumAuth\Validators;

use Ns147\SodiumAuth\Claims\Collection;
use Ns147\SodiumAuth\Exceptions\TokenInvalidException;

class PayloadValidator extends Validator
{
    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * The refresh TTL.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * Run the validations on the payload array.
     *
     * @param  \Ns147\SodiumAuth\Claims\Collection  $value
     *
     * @return \Ns147\SodiumAuth\Claims\Collection
     */
    public function check($value)
    {
        $this->validateStructure($value);

        return $this->refreshFlow ? $this->validateRefresh($value) : $this->validatePayload($value);
    }

    /**
     * Ensure the payload contains the required claims and
     * the claims have the relevant type.
     *
     * @param  \Ns147\SodiumAuth\Claims\Collection  $claims
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     *
     * @return void
     */
    protected function validateStructure(Collection $claims)
    {
        if (! $claims->hasAllClaims($this->requiredClaims)) {
            throw new TokenInvalidException('Token payload does not contain the required claims');
        }
    }

    /**
     * Validate the payload timestamps.
     *
     * @param  \Ns147\SodiumAuth\Claims\Collection  $claims
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenExpiredException
     * @throws \Ns147\SodiumAuth\Exceptions\TokenInvalidException
     *
     * @return \Ns147\SodiumAuth\Claims\Collection
     */
    protected function validatePayload(Collection $claims)
    {
        return $claims->validate('payload');
    }

    /**
     * Check the token in the refresh flow context.
     *
     * @param  \Ns147\SodiumAuth\Claims\Collection  $claims
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenExpiredException
     *
     * @return \Ns147\SodiumAuth\Claims\Collection
     */
    protected function validateRefresh(Collection $claims)
    {
        return $this->refreshTTL === null ? $claims : $claims->validate('refresh', $this->refreshTTL);
    }

    /**
     * Set the required claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;

        return $this;
    }

    /**
     * Set the refresh ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = $ttl;

        return $this;
    }
}
