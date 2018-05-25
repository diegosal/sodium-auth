<?php

namespace Ns147\SodiumAuth\Http\Parser;

use Illuminate\Http\Request;
use Ns147\SodiumAuth\Contracts\Http\Parser as ParserContract;

class QueryString implements ParserContract
{
    use KeyTrait;

    /**
     * Try to parse the token from the request query string.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request)
    {
        return $request->query($this->key);
    }
}
