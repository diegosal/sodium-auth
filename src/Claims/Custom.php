<?php

namespace Ns147\SodiumAuth\Claims;

class Custom extends Claim
{
    /**
     * @param  string  $name
     * @param  mixed  $value
     *
     * @return void
     */
    public function __construct($name, $value)
    {
        parent::__construct($value);
        $this->setName($name);
    }
}
