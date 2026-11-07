<?php

namespace Openframe\PluginMarketSdk\Console;

use Illuminate\Console\Command;
use Openframe\PluginMarketSdk\Signature\SignatureVerifier;
use Openframe\PluginMarketSdk\Validation\PluginMarketException;
use ZipArchive;

class PluginVerifyCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'plugin:verify {path : Path to the plugin zip package}';

    /**
     * The console command description.
     */
    protected $description = 'Verify the signature manifest of a plugin zip package';

    public function __construct(private readonly SignatureVerifier $verifier)
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

        $zip = new ZipArchive;
        $zip->open($path);

        try {
            $result = $this->verifier->verify($zip, basename($path));
        } catch (PluginMarketException $exception) {
            $this->error(sprintf('验签失败：%s', $exception->getMessage()));

            return self::FAILURE;
        } finally {
            $zip->close();
        }

        $this->info('签名校验通过：');
        $this->line(sprintf('  key_id    ：%s', $result['key_id']));
        $this->line(sprintf('  平台背书  ：%s', $result['endorsed'] ? '是' : '否'));
        $this->line(sprintf('  sha256    ：%s', $result['sha256']));
        $this->line(sprintf('  签名时间  ：%s', $result['signed_at']));

        return self::SUCCESS;
    }
}
