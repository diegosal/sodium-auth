<?php


namespace Ns147\SodiumAuth\Facades;

use Illuminate\Support\Facades\Facade;

class SodiumAuth extends Facade
{
    /**
     * Get the registered name of the component.
     *
     * @return string
     */
    protected static function getFacadeAccessor()
    {
        return 'ns147.sodium.auth';
    }
}
