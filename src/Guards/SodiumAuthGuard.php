<?php
namespace Ns147\SodiumAuth\Guards;

use BadMethodCallException;
use Illuminate\Http\Request;
use Illuminate\Auth\GuardHelpers;
use Illuminate\Contracts\Auth\Guard;
use Ns147\SodiumAuth\Contracts\TokenSubject;
use Ns147\SodiumAuth\Exceptions\TokenException;
use Illuminate\Contracts\Auth\UserProvider;
use Ns147\SodiumAuth\Exceptions\UserNotDefinedException;
use Ns147\SodiumAuth\SodiumAuth;

class SodiumAuthGuard implements Guard
{
    use GuardHelpers;

    /**
     * The user we last attempted to retrieve.
     *
     * @var \Illuminate\Contracts\Auth\Authenticatable
     */
    protected $lastAttempted;

    /**
     * The SodiumAuth instance.
     *
     * @var \Ns147\SodiumAuth\SodiumAuth
     */
    protected $sodiumAuth;

    /**
     * The request instance.
     *
     * @var \Illuminate\Http\Request
     */
    protected $request;

    /**
     * Instantiate the class.
     *
     * @param  \Ns147\SodiumAuth\SodiumAuth  $sodiumAuth
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     * @param  \Illuminate\Http\Request  $request
     *
     * @return void
     */
    public function __construct(SodiumAuth $sodiumAuth, UserProvider $provider, Request $request)
    {
        $this->sodiumAuth = $sodiumAuth;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->sodiumAuth->setRequest($this->request)->getToken() &&
            ($payload = $this->sodiumAuth->check(true)) &&
            $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById($payload['sub']);
        }
    }

    /**
     * Get the currently authenticated user or throws an exception.
     *
     * @throws \Ns147\SodiumAuth\Exceptions\UserNotDefinedException
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function userOrFail()
    {
        if (! $user = $this->user()) {
            throw new UserNotDefinedException;
        }

        return $user;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        return (bool) $this->attempt($credentials, false);
    }

    /**
     * Attempt to authenticate the user using the given credentials and return the token.
     *
     * @param  array  $credentials
     * @param  bool  $login
     *
     * @return bool|string
     */
    public function attempt(array $credentials = [], $login = true)
    {
        $this->lastAttempted = $user = $this->provider->retrieveByCredentials($credentials);

        if ($this->hasValidCredentials($user, $credentials)) {
            return $login ? $this->login($user) : true;
        }

        return false;
    }

    /**
     * Create a token for a user.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $user
     *
     * @return string
     */
    public function login(TokenSubject $user)
    {
        $token = $this->sodiumAuth->fromUser($user);
        $this->setToken($token)->setUser($user);

        return $token;
    }

    /**
     * Logout the user, thus invalidating the token.
     *
     * @param  bool  $forceForever
     *
     * @return void
     */
    public function logout($forceForever = false)
    {
        $this->requireToken()->invalidate($forceForever);

        $this->user = null;
        $this->sodiumAuth->unsetToken();
    }

    /**
     * Refresh the token.
     *
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        return $this->requireToken()->refresh($forceForever, $resetClaims);
    }

    /**
     * Invalidate the token.
     *
     * @param  bool  $forceForever
     *
     * @return \Ns147\SodiumAuth\SodiumAuth
     */
    public function invalidate($forceForever = false)
    {
        return $this->requireToken()->invalidate($forceForever);
    }

    /**
     * Create a new token by User id.
     *
     * @param  mixed  $id
     *
     * @return string|null
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            return $this->sodiumAuth->fromUser($user);
        }
    }

    /**
     * Log a user into the application using their credentials.
     *
     * @param  array  $credentials
     *
     * @return bool
     */
    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    /**
     * Log the given User into the application.
     *
     * @param  mixed  $id
     *
     * @return bool
     */
    public function onceUsingId($id)
    {
        if ($user = $this->provider->retrieveById($id)) {
            $this->setUser($user);

            return true;
        }

        return false;
    }

    /**
     * Alias for onceUsingId.
     *
     * @param  mixed  $id
     *
     * @return bool
     */
    public function byId($id)
    {
        return $this->onceUsingId($id);
    }

    /**
     * Add any custom claims.
     *
     * @param  array  $claims
     *
     * @return $this
     */
    public function claims(array $claims)
    {
        $this->sodiumAuth->claims($claims);

        return $this;
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function getPayload()
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Alias for getPayload().
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function payload()
    {
        return $this->getPayload();
    }

    /**
     * Set the token.
     *
     * @param  \Ns147\SodiumAuth\Token|string  $token
     *
     * @return $this
     */
    public function setToken($token)
    {
        $this->sodiumAuth->setToken($token);

        return $this;
    }

    /**
     * Set the token ttl.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setTTL($ttl)
    {
        $this->sodiumAuth->factory()->setTTL($ttl);

        return $this;
    }

    /**
     * Get the user provider used by the guard.
     *
     * @return \Illuminate\Contracts\Auth\UserProvider
     */
    public function getProvider()
    {
        return $this->provider;
    }

    /**
     * Set the user provider used by the guard.
     *
     * @param  \Illuminate\Contracts\Auth\UserProvider  $provider
     *
     * @return $this
     */
    public function setProvider(UserProvider $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    /**
     * Return the currently cached user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function getUser()
    {
        return $this->user;
    }

    /**
     * Get the current request instance.
     *
     * @return \Illuminate\Http\Request
     */
    public function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    /**
     * Set the current request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    /**
     * Get the last user we attempted to authenticate.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable
     */
    public function getLastAttempted()
    {
        return $this->lastAttempted;
    }

    /**
     * Determine if the user matches the credentials.
     *
     * @param  mixed  $user
     * @param  array  $credentials
     *
     * @return bool
     */
    protected function hasValidCredentials($user, $credentials)
    {
        return $user !== null && $this->provider->validateCredentials($user, $credentials);
    }

    /**
     * Ensure the TokenSubject matches what is in the token.
     *
     * @return  bool
     */
    protected function validateSubject()
    {
        // If the provider doesn't have the necessary method
        // to get the underlying model name then allow.
        if (! method_exists($this->provider, 'getModel')) {
            return true;
        }

        return $this->sodiumAuth->checkSubjectModel($this->provider->getModel());
    }

    /**
     * Ensure that a token is available in the request.
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return \Ns147\SodiumAuth\SodiumAuth
     */
    protected function requireToken()
    {
        if (! $this->sodiumAuth->setRequest($this->getRequest())->getToken()) {
            throw new TokenException('Token could not be parsed from the request.');
        }

        return $this->sodiumAuth;
    }

    /**
     * Magically call the SodiumAuth instance.
     *
     * @param  string  $method
     * @param  array  $parameters
     *
     * @throws \BadMethodCallException
     *
     * @return mixed
     */
    public function __call($method, $parameters)
    {
        if (method_exists($this->sodiumAuth, $method)) {
            return call_user_func_array([$this->sodiumAuth, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
