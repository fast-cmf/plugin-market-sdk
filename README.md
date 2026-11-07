# openframe/plugin-market-sdk

Laravel 插件市场的**签名分发 SDK**：Ed25519 包签名、三重验签、密钥管理与吊销列表，基于 PHP 内置 libsodium，零额外扩展依赖。

## 特性

- **包签名**：`signature.json` 签名清单写入模块根目录，规范化内容哈希（与 zip 元数据无关，重打包不影响校验）
- **三重校验**：开发者签名 → 内容 SHA-256 → 平台背书（可选）
- **信任源**：配置键注册 + `{keyId}.pub` 文件扫描
- **吊销列表**：本地 JSON + 每日缓存，`RevocationProvider` 接口预留 HTTP 拉取
- **三档模式**：`strict`（拒绝）/ `permissive`（警告放行）/ `off`（跳过），未知值 fail-closed

## 安装

```bash
composer require openframe/plugin-market-sdk
php artisan vendor:publish --tag=plugin-market-sdk-config
```

要求：PHP ^8.3、ext-sodium（PHP 内置）、ext-zip。

## 使用

### 签名工作流（开发者侧）

```bash
php artisan plugin:keygen --name=my-dev-key   # 生成 Ed25519 密钥对
php artisan plugin:sign path/to/package.zip --key=storage/app/plugin-keys/my-dev-key.sk
php artisan plugin:verify path/to/package.zip  # 调试验证
```

### 验签接入（框架侧）

```php
use Openframe\PluginMarketSdk\Validation\PluginArchiveValidator;

$manifest = app(PluginArchiveValidator::class)->validate($zipPath);
// 验签失败抛 PluginMarketException（strict 模式）
// permissive 模式下警告收集在 ->signatureWarnings()
```

### 错误码

| 常量 | 含义 |
|------|------|
| `UNSIGNED_PACKAGE` | 包内无签名清单 |
| `INVALID_SIGNATURE` | 签名/清单被篡改 |
| `TAMPERED_PACKAGE` | 内容哈希失配 |
| `UNKNOWN_KEY` | 签名密钥未注册 |
| `REVOKED_KEY` | 签名密钥已吊销 |

## 配置

```php
'signing' => [
    'mode' => env('PLUGIN_MARKET_SIGNING_MODE', 'permissive'),
    'keys' => [],                                             // keyId => base64 公钥
    'keys_path' => storage_path('app/plugin-keys'),           // {keyId}.pub 扫描目录
    'revocations_path' => storage_path('app/plugin-revocations.json'),
],
```

## License

[MIT](LICENSE)
