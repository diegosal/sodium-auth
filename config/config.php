<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Encryption Keys
    |--------------------------------------------------------------------------
    |
    | Sodium Auht uses encryption keys while generating secure access tokens for
    | your application. By default, the keys are stored as local files but
    | can be set via environment variables when that is more convenient.
    |
    */

    'key_path' => [
        'p_path' => env('SODIUM_AUTH_P_PATH'),
        'e_path' => env('SODIUM_AUTH_E_PATH'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Keys
    |--------------------------------------------------------------------------
    |
    | Sodium Auht uses encryption keys while generating secure access tokens for
    | your application. By default, the keys are stored as local files but
    | can be set via environment variables when that is more convenient.
    |
    */

    'paseto' => [
        'private_key' => env('SODIUM_AUTH_P_PATH'),
        'public_key' => env('SODIUM_AUTH_E_PATH'),
        'shared_key' => env('SODIUM_AUTH_E_PATH'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sodium Auth Shared Keys
    |--------------------------------------------------------------------------
    |
    |   Authentication & Encryption keys.
    */

    'shared'  => [
        'authentication_key' => env('SAPIENT_SHARED_AUTHENTICATION_KEY'),
        'encryption_key'     => env('SAPIENT_SHARED_ENCRYPTION_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sodium Auth Sealing Keys
    |--------------------------------------------------------------------------
    |
    |   Private & Public keys.
    */

    'sealing' => [
        'private_key' => env('SAPIENT_SEALING_PRIVATE_KEY'),
        'public_key'  => env('SAPIENT_SEALING_PUBLIC_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Sodium Auth Signing Keys
    |--------------------------------------------------------------------------
    |
    |   Private & Public keys.
    */

    'signing' => [
        'private_key' => env('SAPIENT_SIGNING_PRIVATE_KEY'),
        'public_key'  => env('SAPIENT_SIGNING_PUBLIC_KEY'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Time To Live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token will be valid for.
    | Defaults to 1 hour.
    |
    | You can also set this to null, to yield a never expiring token.
    | Some people may want this behaviour for e.g. a mobile app.
    | This is not particularly recommended, so make sure you have appropriate
    | systems in place to revoke the token if necessary.
    |
    */

    'ttl' => env('SODIUM_TTL', 60),

    /*
    |--------------------------------------------------------------------------
    | Refresh Time To Live
    |--------------------------------------------------------------------------
    |
    | Specify the length of time (in minutes) that the token can be refreshed
    | within. I.E. The user can refresh their token within a 2 week window of
    | the original token being created until they must re-authenticate.
    | Defaults to 2 weeks.
    |
    | You can also set this to null, to yield an infinite refresh time.
    | Some may want this instead of never expiring tokens for e.g. a mobile app.
    | This is not particularly recommended, so make sure you have appropriate
    | systems in place to revoke the token if necessary.
    |
    */

    'refresh_ttl' => env('SODIUM_REFRESH_TTL', 20160),

];
