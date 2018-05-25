<?php

namespace Ns147\SodiumAuth\Controllers;

use App\Http\Controllers\Controller;
use Carbon\Carbon;
use ParagonIE\Paseto\Builder;
use ParagonIE\Paseto\Exception\PasetoException;
use ParagonIE\Paseto\Parser;
use ParagonIE\Paseto\Purpose;
use ParagonIE\Paseto\Rules\{
    IssuedBy,
    NotExpired
};
use ParagonIE\Paseto\ProtocolCollection;
use League\OAuth2\Server\AuthorizationServer;
use ParagonIE\Paseto\Keys\AsymmetricSecretKey;
use ParagonIE\Paseto\Keys\AsymmetricPublicKey;
use ParagonIE\Paseto\Protocol\Version2;
class SodiumAuthController  extends Controller
{

    public function  __Construct()
    {
    }

    public function index()
    {
        $private = AsymmetricSecretKey::fromEncodedString(config('sodium.paseto.private_key'));

        $token = (new Builder())
        ->setKey($private)
        ->setVersion(new Version2())
        ->setPurpose(Purpose::public())
        ->setExpiration(Carbon::now()->addMinutes(60))
        ->setClaims([
            'sub' => 0,
            'csrf' => '',
        ]);

        $parser = (new Parser())
            ->setKey($private->getPublicKey())
            ->setPurpose(Purpose::public())
            ->setAllowedVersions(ProtocolCollection::v2());

        $parts = explode('.', $token->toString());

        if (count($parts) !== 3) {
            throw new Exception('Wrong number of segments');
        }

        $parts = array_filter(array_map('trim', $parts));

        if (count($parts) !== 3 || implode('.', $parts) !== $token->toString()) {
            throw new Exception('Malformed token');
        }

        try {
            $token = $parser->parse($token);
        } catch (PasetoException $ex) {
            throw new Exception($ex->getMessage());
        }

        echo '<pre>';
        var_dumP($token->getClaims());
        echo '</pre>';
    }
}
