<?php

namespace Openframe\PluginMarketSdk\Console;

use Illuminate\Console\Command;
use Openframe\PluginMarketSdk\Signature\PackageSigner;
use Openframe\PluginMarketSdk\Signature\SigningKey;

class PluginSignCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'plugin:sign
        {path : Path to the plugin zip package}
        {--key= : Path to the secret key (.sk) file}';

    /**
     * The console command description.
     */
    protected $description = 'Sign a plugin zip package by appending a signature.json manifest';

    public function __construct(private readonly PackageSigner $signer)
    {
        parent::__construct();
    }

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $path = (string) $this->argument('path');

        if (! is_file($path)) {
            $this->error(sprintf('插件包不存在：%s', $path));

            return self::FAILURE;
        }

        $key = SigningKey::fromSecretKeyFile(
            SigningKey::resolveSecretKeyPath((string) $this->option('key')),
        );

        $document = $this->signer->sign($path, $key);

        $this->info(sprintf('插件包签名完成：%s', $path));
        $this->line(sprintf('  key_id  ：%s', $document['key_id']));
        $this->line(sprintf('  sha256  ：%s', $document['sha256']));
        $this->line(sprintf('  签名时间：%s', $document['signed_at']));

        return self::SUCCESS;
    }
}
