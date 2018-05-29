<?php

namespace Ns147\SodiumAuth\Exceptions;

use Exception;
use Ns147\SodiumAuth\Claims\Claim;

class InvalidClaimException extends TokenException
{
    /**
     * Constructor.
     *
     * @param  \Ns147\SodiumAuth\Claims\Claim  $claim
     * @param  int  $code
     * @param  \Exception|null  $previous
     *
     * @return void
     */
    public function __construct(Claim $claim, $code = 0, Exception $previous = null)
    {
        parent::__construct('Invalid value provided for claim ['.$claim->getName().']', $code, $previous);
    }
}
