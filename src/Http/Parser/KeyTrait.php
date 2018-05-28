<?php

namespace Ns147\SodiumAuth\Http\Parser;

trait KeyTrait
{
    /**
     * The key.
     *
     * @var string
     */
    protected $key = 'token';

    /**
     * Set the key.
     *
     * @param  string  $key
     *
     * @return $this
     */
    public function setKey($key)
    {
        $this->key = $key;

        return $this;
    }

    /**
     * Get the key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }
}
