<?php

namespace Ns147\SodiumAuth;

use BadMethodCallException;
use Illuminate\Http\Request;
use Ns147\SodiumAuth\Http\Parser\Parser;
use Ns147\SodiumAuth\Support\CustomClaims;
use Ns147\SodiumAuth\Exceptions\TokenException;
use Ns147\SodiumAuth\Contracts\TokenSubject;
class SodiumAuth
{
    use CustomClaims;

    /**
     * The authentication manager.
     *
     * @var \Ns147\SodiumAuth\Manager
     */
    protected $manager;

    /**
     * The HTTP parser.
     *
     * @var \Ns147\SodiumAuth\Http\Parser\Parser
     */
    protected $parser;

    /**
     * The token.
     *
     * @var \Ns147\SodiumAuth\Token|null
     */
    protected $token;

    /**
     * Lock the subject.
     *
     * @var bool
     */
    protected $lockSubject = true;

    /**
     * SodiumAuth constructor.
     *
     * @param  \Ns147\SodiumAuth\Manager  $manager
     * @param  \Ns147\SodiumAuth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Parser $parser)
    {
        $this->manager = $manager;
        $this->parser = $parser;
    }

    /**
     * Generate a token for a given subject.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $subject
     *
     * @return string
     */
    public function fromSubject(TokenSubject $subject)
    {
        $payload = $this->makePayload($subject);

        return $this->manager->encode($payload)->get();
    }

    /**
     * Alias to generate a token for a given user.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $user
     *
     * @return string
     */
    public function fromUser(TokenSubject $user)
    {
        return $this->fromSubject($user);
    }

    /**
     * Refresh an expired token.
     *
     * @param  bool  $forceForever
     * @param  bool  $resetClaims
     *
     * @return string
     */
    public function refresh($forceForever = false, $resetClaims = false)
    {
        $this->requireToken();

        return $this->manager->customClaims($this->getCustomClaims())
                             ->refresh($this->token, $forceForever, $resetClaims)
                             ->get();
    }

    /**
     * Invalidate a token (add it to the blacklist).
     *
     * @param  bool  $forceForever
     *
     * @return $this
     */
    public function invalidate($forceForever = false)
    {
        $this->requireToken();

        $this->manager->invalidate($this->token, $forceForever);

        return $this;
    }

    /**
     * Alias to get the payload, and as a result checks that
     * the token is valid i.e. not expired or blacklisted.
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function checkOrFail()
    {
        return $this->getPayload();
    }

    /**
     * Check that the token is valid.
     *
     * @param  bool  $getPayload
     *
     * @return \Ns147\SodiumAuth\Payload|bool
     */
    public function check($getPayload = false)
    {
        try {
            $payload = $this->checkOrFail();
        } catch (TokenException $e) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    /**
     * Get the token.
     *
     * @return \Ns147\SodiumAuth\Token|null
     */
    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch (TokenException $e) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    /**
     * Parse the token from the request.
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return $this
     */
    public function parseToken()
    {
        if (! $token = $this->parser->parseToken()) {
            throw new TokenException('The token could not be parsed from the request');
        }

        return $this->setToken($token);
    }

    /**
     * Get the raw Payload instance.
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode($this->token);
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
     * Convenience method to get a claim value.
     *
     * @param  string  $claim
     *
     * @return mixed
     */
    public function getClaim($claim)
    {
        return $this->payload()->get($claim);
    }

    /**
     * Create a Payload instance.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $subject
     *
     * @return \Ns147\SodiumAuth\Payload
     */
    public function makePayload(TokenSubject $subject)
    {
        return $this->factory()->customClaims($this->getClaimsArray($subject))->make();
    }

    /**
     * Build the claims array and return it.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $subject
     *
     * @return array
     */
    protected function getClaimsArray(TokenSubject $subject)
    {
        return array_merge(
            $this->getClaimsForSubject($subject),
            $subject->getTokenCustomClaims(), // custom claims from TokenSubject method
            $this->customClaims // custom claims from inline setter
        );
    }

    /**
     * Get the claims associated with a given subject.
     *
     * @param  \Ns147\SodiumAuth\Contracts\TokenSubject  $subject
     *
     * @return array
     */
    protected function getClaimsForSubject(TokenSubject $subject)
    {
        return array_merge([
            'sub' => $subject->getTokenIdentifier(),
        ], $this->lockSubject ? ['prv' => $this->hashSubjectModel($subject)] : []);
    }

    /**
     * Hash the subject model and return it.
     *
     * @param  string|object  $model
     *
     * @return string
     */
    protected function hashSubjectModel($model)
    {
        return sha1(is_object($model) ? get_class($model) : $model);
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param  string|object  $model
     *
     * @return bool
     */
    public function checkSubjectModel($model)
    {
        if (($prv = $this->payload()->get('prv')) === null) {
            return true;
        }

        return $this->hashSubjectModel($model) === $prv;
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
        $this->token = $token instanceof Token ? $token : new Token($token);

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    /**
     * Ensure that a token is available.
     *
     * @throws \Ns147\SodiumAuth\Exceptions\TokenException
     *
     * @return void
     */
    protected function requireToken()
    {
        if (! $this->token) {
            throw new TokenException('A token is required');
        }
    }

    /**
     * Set the request instance.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return $this
     */
    public function setRequest(Request $request)
    {
        $this->parser->setRequest($request);

        return $this;
    }

    /**
     * Set whether the subject should be "locked".
     *
     * @param  bool  $lock
     *
     * @return $this
     */
    public function lockSubject($lock)
    {
        $this->lockSubject = $lock;

        return $this;
    }

    /**
     * Get the Manager instance.
     *
     * @return \Ns147\SodiumAuth\Manager
     */
    public function manager()
    {
        return $this->manager;
    }

    /**
     * Get the Parser instance.
     *
     * @return \Ns147\SodiumAuth\Http\Parser\Parser
     */
    public function parser()
    {
        return $this->parser;
    }

    /**
     * Get the Payload Factory.
     *
     * @return \Ns147\SodiumAuth\Factory
     */
    public function factory()
    {
        return $this->manager->getPayloadFactory();
    }

    /**
     * Get the Blacklist.
     *
     * @return \Ns147\SodiumAuth\Blacklist
     */
    public function blacklist()
    {
        return $this->manager->getBlacklist();
    }

    /**
     * Magically call the Token Manager.
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
        if (method_exists($this->manager, $method)) {
            return call_user_func_array([$this->manager, $method], $parameters);
        }

        throw new BadMethodCallException("Method [$method] does not exist.");
    }
}
