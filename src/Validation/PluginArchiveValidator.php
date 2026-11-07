<?php

namespace Openframe\PluginMarketSdk\Validation;

use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Process;
use Illuminate\Support\Str;
use Openframe\PluginMarketSdk\Signature\SignatureVerifier;
use ZipArchive;

class PluginArchiveValidator
{
    /**
     * Signature warnings collected during the last validate() call
     * (permissive mode keeps the package but records the problems).
     *
     * @var list<string>
     */
    private array $signatureWarnings = [];

    /**
     * Signature metadata of the last validate() call, or null when the
     * package carries no verifiable signature.
     *
     * @var array{key_id: string, endorsed: bool, sha256: string, signed_at: string}|null
     */
    private ?array $signatureInfo = null;

    public function __construct(private readonly SignatureVerifier $signatures) {}

    /**
     * Validate a plugin zip archive and extract its manifest.
     *
     * @return PluginManifestData The parsed manifest.
     *
     * @throws PluginMarketException When the archive is not a valid plugin package.
     */
    public function validate(string $zipPath): PluginManifestData
    {
        $this->signatureWarnings = [];
        $this->signatureInfo = null;

        $zip = $this->openArchive($zipPath);

        try {
            $this->verifySignature($zip, $zipPath);
            $entries = $this->collectEntries($zip);
            $name = $this->assertSingleRootDirectory($entries);
            $manifest = $this->readManifest($zip, $name);
            $this->assertPhpVersion($manifest);
            $this->assertRequiredModules($manifest);
            $this->assertProviderFiles($zip, $entries, $manifest);
            $this->lintPhpFiles($zip, $entries, $manifest);
        } finally {
            $zip->close();
        }

        return $manifest;
    }

    /**
     * Signature warnings collected during the last validate() call.
     *
     * @return list<string>
     */
    public function signatureWarnings(): array
    {
        return $this->signatureWarnings;
    }

    /**
     * Signature metadata collected during the last validate() call.
     *
     * @return array{key_id: string, endorsed: bool, sha256: string, signed_at: string}|null
     */
    public function signatureInfo(): ?array
    {
        return $this->signatureInfo;
    }

    /**
     * Run package signature verification according to signing.mode:
     * `strict` rejects unverifiable packages, `permissive` collects
     * warnings, `off` skips verification entirely (unknown values
     * behave like strict, i.e. fail closed).
     */
    private function verifySignature(ZipArchive $zip, string $zipPath): void
    {
        $mode = (string) config('plugin-market.signing.mode', 'permissive');

        if ($mode === 'off') {
            return;
        }

        try {
            $this->signatureInfo = $this->signatures->verify($zip, basename($zipPath));
        } catch (PluginMarketException $exception) {
            if ($mode !== 'permissive') {
                throw $exception;
            }

            $this->signatureWarnings[] = $exception->getMessage();
        }
    }

    /**
     * Open the zip and ensure it is a valid archive.
     */
    private function openArchive(string $zipPath): ZipArchive
    {
        if (! is_file($zipPath)) {
            throw new PluginMarketException('插件包文件不存在。');
        }

        $zip = new ZipArchive;

        $code = $zip->open($zipPath, ZipArchive::CHECKCONS);

        if ($code !== true || $zip->numFiles === 0) {
            throw new PluginMarketException('无法读取插件包，请确认上传的是有效的 zip 文件。');
        }

        return $zip;
    }

    /**
     * Collect all non-directory entry names and reject path traversal attempts.
     *
     * @return list<string>
     */
    private function collectEntries(ZipArchive $zip): array
    {
        $entries = [];

        for ($index = 0; $index < $zip->numFiles; $index++) {
            $entry = (string) $zip->getNameIndex($index);

            if (str_contains($entry, '..') || str_contains($entry, '\\') || preg_match('#^[A-Za-z]:/#', $entry) === 1) {
                throw new PluginMarketException('插件包内包含非法路径条目，已拒绝安装。');
            }

            if ($entry === '' || str_ends_with($entry, '/')) {
                continue;
            }

            $entries[] = $entry;
        }

        return $entries;
    }

    /**
     * Ensure every file lives under one unique StudlyCase root directory.
     *
     * @param  list<string>  $entries
     */
    private function assertSingleRootDirectory(array $entries): string
    {
        $roots = [];

        foreach ($entries as $entry) {
            $roots[] = (string) str($entry)->before('/');
        }

        $roots = array_values(array_unique($roots));

        if (count($roots) !== 1) {
            throw new PluginMarketException('插件包必须只包含一个根目录（模块目录名）。');
        }

        $name = $roots[0];

        if (preg_match('/^[A-Z][A-Za-z0-9]{1,63}$/', $name) !== 1) {
            throw new PluginMarketException(sprintf('模块目录名 "%s" 不合法，必须为合法的 StudlyCase 名称（字母开头，2-64 位）。', $name));
        }

        return $name;
    }

    /**
     * Read and validate module.json.
     */
    private function readManifest(ZipArchive $zip, string $name): PluginManifestData
    {
        $contents = $zip->getFromName($name.'/module.json');

        if ($contents === false) {
            throw new PluginMarketException('插件包缺少 module.json 清单文件。');
        }

        $json = json_decode($contents, true);

        if (! is_array($json)) {
            throw new PluginMarketException('module.json 不是合法的 JSON 文件。');
        }

        foreach (['name', 'alias', 'version', 'description', 'providers'] as $field) {
            if (! Arr::has($json, $field) || Arr::get($json, $field) === '' || Arr::get($json, $field) === null) {
                throw new PluginMarketException(sprintf('module.json 缺少必填字段 "%s"。', $field));
            }
        }

        if ((string) $json['name'] !== $name) {
            throw new PluginMarketException(sprintf('module.json 的 name "%s" 与包内目录名 "%s" 不一致。', $json['name'], $name));
        }

        if (preg_match('/^[a-z][a-z0-9_\-]{1,63}$/', (string) $json['alias']) !== 1) {
            throw new PluginMarketException(sprintf('别名 "%s" 不合法，必须为小写字母开头的 2-64 位标识。', $json['alias']));
        }

        if (preg_match('/^\d+\.\d+\.\d+(-[\w.]+)?$/', (string) $json['version']) !== 1) {
            throw new PluginMarketException(sprintf('版本号 "%s" 不合法，必须符合语义化版本（如 1.0.0）。', $json['version']));
        }

        $manifest = PluginManifestData::fromArray($json);

        if ($manifest->providers === []) {
            throw new PluginMarketException('module.json 必须声明至少一个 ServiceProvider。');
        }

        return $manifest;
    }

    /**
     * Check required_php against the current runtime.
     */
    private function assertPhpVersion(PluginManifestData $manifest): void
    {
        if ($manifest->requiredPhp === null) {
            return;
        }

        if (version_compare(PHP_VERSION, str_replace(['^', '~'], '', $manifest->requiredPhp), '<')) {
            throw new PluginMarketException(sprintf(
                '插件要求 PHP %s，当前运行环境为 %s，版本不兼容。',
                $manifest->requiredPhp,
                PHP_VERSION,
            ));
        }
    }

    /**
     * Check that every required module is already present and enabled.
     */
    private function assertRequiredModules(PluginManifestData $manifest): void
    {
        if ($manifest->requiredModules === []) {
            return;
        }

        $statuses = $this->moduleStatuses();
        $missing = [];

        foreach ($manifest->requiredModules as $alias) {
            if (! isset($statuses[$alias]) || $statuses[$alias] !== true) {
                $missing[] = $alias;
            }
        }

        if ($missing !== []) {
            throw new PluginMarketException(sprintf('插件依赖以下模块，但它们未安装或未启用：%s。', implode('、', $missing)));
        }
    }

    /**
     * Ensure each declared provider class maps to an existing file inside the zip.
     *
     * @param  list<string>  $entries
     */
    private function assertProviderFiles(ZipArchive $zip, array $entries, PluginManifestData $manifest): void
    {
        foreach ($manifest->providers as $provider) {
            $relative = $this->providerToPath($manifest->name, $provider);

            if (! in_array($relative, $entries, true)) {
                throw new PluginMarketException(sprintf('声明的服务提供者 %s 对应文件 %s 在插件包中不存在。', $provider, $relative));
            }

            if ($zip->getFromName($relative) === false) {
                throw new PluginMarketException(sprintf('无法读取插件包中的文件 %s。', $relative));
            }
        }
    }

    /**
     * Map a provider FQCN to its zip entry path.
     * Module PSR-4 root maps `Modules\{Name}\` to the module's `app/` directory.
     */
    private function providerToPath(string $name, string $provider): string
    {
        $relative = Str::startsWith($provider, 'Modules\\'.$name.'\\')
            ? 'app/'.Str::after($provider, 'Modules\\'.$name.'\\')
            : $provider;

        return $name.'/'.str_replace('\\', '/', $relative).'.php';
    }

    /**
     * Run `php -l` against provider files and route files to catch syntax errors
     * before enabling the module (prevents a broken package from 500-ing the app).
     *
     * @param  list<string>  $entries
     */
    private function lintPhpFiles(ZipArchive $zip, array $entries, PluginManifestData $manifest): void
    {
        $targets = [];

        foreach ($manifest->providers as $provider) {
            $targets[] = $this->providerToPath($manifest->name, $provider);
        }

        foreach ($entries as $entry) {
            if (str_starts_with($entry, $manifest->name.'/routes/') && str_ends_with($entry, '.php')) {
                $targets[] = $entry;
            }
        }

        foreach ($targets as $entry) {
            $code = $zip->getFromName($entry);

            if ($code === false) {
                continue;
            }

            $tempFile = tempnam(sys_get_temp_dir(), 'plugin-lint-');

            try {
                file_put_contents($tempFile, $code);

                $result = Process::run([PHP_BINARY, '-l', $tempFile]);

                if (! str_contains((string) $result->errorOutput(), 'No syntax errors')
                    && ! str_contains((string) $result->output(), 'No syntax errors')) {
                    throw new PluginMarketException(sprintf('插件包内文件 %s 存在 PHP 语法错误，已拒绝安装。', $entry));
                }
            } finally {
                @unlink($tempFile);
            }
        }
    }

    /**
     * Read the module status file (alias => enabled).
     *
     * @return array<string, bool>
     */
    private function moduleStatuses(): array
    {
        $path = (string) config('plugin-market.paths.statuses');

        if (! is_file($path)) {
            return [];
        }

        $decoded = json_decode((string) file_get_contents($path), true);

        return is_array($decoded) ? $decoded : [];
    }
}
