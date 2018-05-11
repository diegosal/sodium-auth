<?php

namespace Ns147\SodiumAuth\Providers;

use Illuminate\Support\ServiceProvider;

class SodiumAuthServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap services.
     *
     * @return void
     */
    public function boot()
    {
        //
    }

    /**
     * Register services.
     *
     * @return void
     */
    public function register()
    {
        include __DIR__.'/routes/web.php';
        $this->app->make('Ns147\SodiumAuth\Controllers\SodiumAuthController');
    }
}
