<?php

namespace Ns147\SodiumAuth\Contracts\Providers;

interface Token
{
    /**
     * @param  array  $payload
     *
     * @return string
     */
    public function encode(array $payload);

    /**
     * @param  string  $token
     *
     * @return \ParagonIE\Paseto\JsonToken
     */
    public function decode($token);
}
