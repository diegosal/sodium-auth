<?php

namespace Ns147\SodiumAuth\Controllers;

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Redis;

class SodiumAuthController  extends Controller
{

    public function index()
    {
        $redis = Redis::connection();
        $redis->set('hola', 'diego');
        $nombre = $redis->get('hola');
        return $nombre;
    }

}