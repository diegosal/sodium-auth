<?php

namespace Ns147\SodiumAuth\Providers;

use Ns147\SodiumAuth\Providers\AbstractServiceProvider;

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
}
