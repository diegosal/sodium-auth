<?php

namespace  Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;
use  Ns147\SodiumAuth\Contracts\SodiumAuthEncrypter;

class EncryptionProvider extends ServiceProvider
{
    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('encrypter', function ($app) {
            $config = $app->make('config')->get('sodium');
            $key = $config['e_path'];

            return new SodiumAuthEncrypter($key);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['encrypter'];
    }
}
