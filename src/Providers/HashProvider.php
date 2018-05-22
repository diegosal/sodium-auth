<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Ns147\SodiumAuth\Contracts\SodiumAuthHasher;

class HashProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = true;

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton('hash', function ($app) {
            $config = $app->make('config')->get('sodium');
            $key = $config['key_path']['p_path'];

            return new SodiumAuthHasher($key);
        });
    }

    /**
     * Get the services provided by the provider.
     *
     * @return array
     */
    public function provides()
    {
        return ['hash'];
    }
}
