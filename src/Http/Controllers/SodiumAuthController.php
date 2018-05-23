<?php

namespace Ns147\SodiumAuth\Controllers;

use App\Http\Controllers\Controller;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\SymmetricKey;

class SodiumAuthController  extends Controller
{

    public function  __Construct()
    {
    }

    public function index()
    {
        $pair = new AsymmetricSecretKey(sodium_crypto_sign_keypair());

        $public = $pair->getPublicKey()->row();
        $private = $pair()->row();
    }

}
