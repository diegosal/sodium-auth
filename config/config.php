<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Authentication Secret
    |--------------------------------------------------------------------------
    |
    | Don't forget to set this in your .env file, as it will be used to sign
    | your tokens. A helper command is provided for this:
    | `php artisan sodium:secret`
    |
    */

    'p_path' => env('SODIUM_AUTH_P_PATH'),

    'e_path' => env('SODIUM_AUTH_E_PATH'),

];