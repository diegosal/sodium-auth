<?php

namespace Ns147\SodiumAuth;

use BadMethodCallException;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Contracts\Auth\UserProvider;
use Ns147\SodiumAuth\Middleware\SharedVerifyRequest;

class SodiumGuard implements Guard
{
    use GuardHelpers;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Instantiate the class.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     *
     * @return void
     */
    public function __construct(UserProvider $provider, Request $request)
    {
        $this->jwt = $jwt;
        $this->provider = $provider;
        $this->request = $request;
    }
}
