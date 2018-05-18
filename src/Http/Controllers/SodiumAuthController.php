<?php

namespace Ns147\SodiumAuth\Controllers;

use App\Http\Controllers\Controller;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
class SodiumAuthController  extends Controller
{

    public function index()
    {
        $secret = new HiddenString(random_bytes(32));
        $salt = random_bytes(16);
        $pKey = KeyFactory::deriveSignatureKeyPair($secret, $salt);
        KeyFactory::save($pKey, '/home/vagrant/code/oauthtest/test.key');
        $pKey = KeyFactory::loadSignatureKeyPair('/home/vagrant/code/oauthtest/test.key');
        $pKey = KeyFactory::importSignaturePublicKey($pKey->getPublicKey());
        var_dump($pKey->getPublicKey());
    }

}
