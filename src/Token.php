<?php

namespace Ns147\SodiumAuth;

use Ns147\SodiumAuth\Validators\TokenValidator;

class Token
{
    /**
     * @var string
     */
    private $value;

    /**
     * Create a new Web Token.
     *
     * @param  string  $value
     *
     * @return void
     */
    public function __construct($value)
    {
        $this->value = (string) (new TokenValidator)->check($value);
    }

    /**
     * Get the token.
     *
     * @return string
     */
    public function get()
    {
        return $this->value;
    }

    /**
     * Get the token when casting to string.
     *
     * @return string
     */
    public function __toString()
    {
        return $this->get();
    }
}
