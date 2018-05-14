<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;
use  Ns147\SodiumAuth\Console\SodiumSecretCommand;

class SodiumAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        $path = realpath(__DIR__.'/../../config/config.php');

        $this->publishes([$path => config_path('sodium.php')], 'config');
        $this->mergeConfigFrom($path, 'sodium');

        // $this->aliasMiddleware();

        // $this->extendAuthGuard();
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        $this->registerSodiumCommand();

        $this->commands('sodium.secret');
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerSodiumCommand()
    {
        $this->app->singleton('sodium.secret', function () {
            return new SodiumSecretCommand;
        });
    }
}
