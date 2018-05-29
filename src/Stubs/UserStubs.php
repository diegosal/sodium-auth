<?php

namespace Ns147\SodiumAuth\Stubs;

use Ns147\SodiumAuth\Contracts\TokenSubject;

class UserStub implements TokenSubject
{
    public function getTokenIdentifier()
    {
        return 1;
    }

    public function getTokenCustomClaims()
    {
        return [
            'foo' => 'bar',
            'role' => 'admin',
        ];
    }
}
