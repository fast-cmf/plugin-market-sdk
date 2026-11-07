<?php

namespace Openframe\PluginMarketSdk\Console;

use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Openframe\PluginMarketSdk\Signature\SigningKey;

class PluginKeygenCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'plugin:keygen
        {--name= : Optional human readable name for the secret key file}
        {--force : Overwrite an existing secret key file with the same name}';

    /**
     * The console command description.
     */
    protected $description = 'Generate an Ed25519 key pair for signing plugin packages';

    /**
     * Execute the console command.
     */
    public function handle(): int
    {
        $keysPath = rtrim((string) config('plugin-market.signing.keys_path'), '/\\');
        $key = SigningKey::generate();

        $name = (string) $this->option('name');

        if ($name === '') {
            $name = $key->keyId();
        }

        if (preg_match('/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/', $name) !== 1) {
            $this->error('密钥名称只能以字母或数字开头，包含字母、数字、点、下划线和连字符（最长 64 位）。');

            return self::FAILURE;
        }

        $secretPath = $keysPath.DIRECTORY_SEPARATOR.$name.'.sk';
        $publicPath = $keysPath.DIRECTORY_SEPARATOR.$key->keyId().'.pub';

        if (is_file($secretPath) && ! $this->option('force')) {
            $this->error(sprintf('私钥文件已存在：%s（如需覆盖请加 --force）', $secretPath));

            return self::FAILURE;
        }

        File::ensureDirectoryExists($keysPath);

        File::put($secretPath, $key->exportSecretKey());
        File::put($publicPath, $key->exportPublicKey());

        $this->info('已生成 Ed25519 签名密钥对：');
        $this->line(sprintf('  key_id      ：%s', $key->keyId()));
        $this->line(sprintf('  私钥文件    ：%s', $secretPath));
        $this->line(sprintf('  公钥文件    ：%s', $publicPath));
        $this->line(sprintf('  公钥(base64)：%s', $key->exportPublicKey()));
        $this->warn('请妥善保管私钥文件，切勿上传到市场或提交到代码仓库；公钥与 key_id 需在市场注册绑定。');

        return self::SUCCESS;
    }
}
