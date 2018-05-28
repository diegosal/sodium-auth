<?php

namespace Ns147\SodiumAuth\Contracts;

interface SodiumAuthSubject
{
    /**
     * Get the identifier that will be stored in the subject claim of the Token.
     *
     * @return mixed
     */
    public function getTokenIdentifier();

    /**
     * Return a key value array, containing any custom claims to be added to the Token.
     *
     * @return array
     */
    public function getTokenCustomClaims();
}
