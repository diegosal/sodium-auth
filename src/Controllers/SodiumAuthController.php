<?php

namespace Ns147\SodiumAuth\Controllers;

use App\Http\Controllers\Controller;
use Carbon\Carbon;

class SodiumAuthController extends Controller
{

    public function index($timezone)
    {
        echo Carbon::now($timezone)->toDateTimeString();
    }

}