<?php

namespace Ns147\SodiumAuth\Exceptions;

use Exception;

class TokenException extends Exception
{
    /**
     * {@inheritdoc}
     */
    protected $message = 'An error occurred';
}
