<?php

namespace Ns147\SodiumAuth;

use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Contracts\Providers\Auth;

class SAuth extends SodiumAuth
{
    /**
     * The authentication provider.
     *
     * @var \Ns147\SodiumAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * Constructor.
     *
     * @param  \Ns147\SodiumAuth\Manager  $manager
     * @param  \Ns147\SodiumAuth\Contracts\Providers\Auth  $auth
     * @param  \Ns147\SodiumAuth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param  array  $credentials
     *
     * @return false|string
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

    /**
     * Authenticate a user via a token.
     *
     * @return \Ns147\SodiumAuth\Contracts\TokenSubject|false
     */
    public function authenticate()
    {
        $id = $this->getPayload()->get('sub');

        if (! $this->auth->byId($id)) {
            return false;
        }

        return $this->user();
    }

    /**
     * Alias for authenticate().
     *
     * @return \Ns147\SodiumAuth\Contracts\TokenSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     *
     * @return \Ns147\SodiumAuth\Contracts\TokenSubject
     */
    public function user()
    {
        return $this->auth->user();
    }
}
