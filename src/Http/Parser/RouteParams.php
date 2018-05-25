<?php

namespace Ns147\SodiumAuth\Http\Parser;

use Illuminate\Http\Request;
use Ns147\SodiumAuth\Contracts\Http\Parser as ParserContract;

class RouteParams implements ParserContract
{
    use KeyTrait;

    /**
     * Try to get the token from the route parameters.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        $route = $request->route();

        // Route may not be an instance of Illuminate\Routing\Route
        // (it's an array in Lumen <5.2) or not exist at all
        // (if the request was never dispatched)
        if (is_callable([$route, 'parameter'])) {
            return $route->parameter($this->key);
        }
    }
}
