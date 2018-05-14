<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;
use  Ns147\SodiumAuth\Console\SodiumSecretCommand;

abstract class AbstractServiceProvider extends ServiceProvider
{
    /**
     * Boot the service provider.
     *
     * @return void
     */
    abstract public function boot();

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
        $this->registerSodiumCommand();

        $this->commands('ns147.sodium.secret');
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerSodiumCommand()
    {
        $this->app->singleton('ns147.sodium.secret', function () {
            return new SodiumSecretCommand;
        });
    }
}