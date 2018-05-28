<?php

namespace Ns147\SodiumAuth\Contracts\Http;

use Illuminate\Http\Request;

interface Parser
{
    /**
     * Parse the request.
     *
     * @param  \Illuminate\Http\Request  $request
     *
     * @return null|string
     */
    public function parse(Request $request);
}
