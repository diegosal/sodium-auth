<?php

namespace  Ns147\SodiumAuth\Test\Stubs;

use  Ns147\SodiumAuth\Contracts\TokenSubject;
use Illuminate\Contracts\Auth\Authenticatable;

class LaravelUserStub extends UserStub implements Authenticatable, TokenSubject
{
    public function getAuthIdentifierName()
    {
        //
    }

    public function getAuthIdentifier()
    {
        //
    }

    public function getAuthPassword()
    {
        //
    }

    public function getRememberToken()
    {
        //
    }

    public function setRememberToken($value)
    {
        //
    }

    public function getRememberTokenName()
    {
        //
    }
}
