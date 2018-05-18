<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;
use Ns147\SodiumAuth\Console\InstallCommand;
use Ns147\SodiumAuth\Controller\SodiumAuthController;

class SodiumAuthServiceProvider extends AbstractServiceProvider
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
        $this->commands('ns147.sodium.install');
        $this->registerController();

    }

     /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerController()
    {
        $this->app->singleton('', function () {
            return new SodiumAuthController;
        });
    }

    /**
     * Register the Artisan command.
     *
     * @return void
     */
    protected function registerSodiumCommand()
    {
        $this->app->singleton('ns147.sodium.install', function () {
            return new InstallCommand;
        });
    }
}
