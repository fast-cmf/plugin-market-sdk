<?php

namespace Openframe\PluginMarketSdk;

use Illuminate\Support\ServiceProvider;
use Openframe\PluginMarketSdk\Console\PluginKeygenCommand;
use Openframe\PluginMarketSdk\Console\PluginSignCommand;
use Openframe\PluginMarketSdk\Console\PluginVerifyCommand;

class PluginMarketSdkServiceProvider extends ServiceProvider
{
    /**
     * Register package configuration defaults.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/plugin-market.php', 'plugin-market');
    }

    /**
     * Publish assets and register the signing console commands.
     */
    public function boot(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__.'/../config/plugin-market.php' => config_path('plugin-market.php'),
        ], 'plugin-market-sdk-config');

        $this->commands([
            PluginKeygenCommand::class,
            PluginSignCommand::class,
            PluginVerifyCommand::class,
        ]);
    }
}
