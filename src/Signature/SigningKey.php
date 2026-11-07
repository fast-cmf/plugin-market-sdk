<?php

namespace Openframe\PluginMarketSdk\Signature;

use Openframe\PluginMarketSdk\Validation\PluginMarketException;

/**
 * An Ed25519 signing key pair backed by PHP's bundled libsodium.
 *
 * The secret key never leaves the machine that generated it; only the
 * public key (and its fingerprint-derived key id) is ever shared.
 */
final class SigningKey
{
    private ?string $keyId = null;

    private function __construct(
        private readonly string $secretKey,
        private readonly string $publicKey,
    ) {}

    /**
     * Generate a brand new key pair.
     */
    public static function generate(): self
    {
        $keypair = sodium_crypto_sign_keypair();

        return new self(
            sodium_crypto_sign_secretkey($keypair),
            sodium_crypto_sign_publickey($keypair),
        );
    }

    /**
     * Load a key pair from a `.sk` file containing the base64 secret key.
     */
    public static function fromSecretKeyFile(string $path): self
    {
        if (! is_file($path)) {
            throw new PluginMarketException(sprintf('私钥文件不存在：%s', $path));
        }

        $raw = base64_decode(trim((string) file_get_contents($path)), true);

        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new PluginMarketException(sprintf('私钥文件 %s 内容不合法，必须是 base64 编码的 Ed25519 私钥。', $path));
        }

        return new self($raw, sodium_crypto_sign_publickey_from_secretkey($raw));
    }

    /**
     * Build a key pair instance from raw key material (mainly for tests).
     */
    public static function fromRaw(string $secretKey, string $publicKey): self
    {
        if (strlen($secretKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES
            || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new PluginMarketException('Ed25519 密钥长度不合法。');
        }

        return new self($secretKey, $publicKey);
    }

    /**
     * Resolve a `.sk` file path: the explicit hint when given, otherwise the
     * only `.sk` file inside the configured key store (convenience for CLI).
     */
    public static function resolveSecretKeyPath(?string $hint): string
    {
        if ($hint !== null && $hint !== '') {
            return $hint;
        }

        $directory = rtrim((string) config('plugin-market.signing.keys_path', storage_path('app/plugin-keys')), '/\\');
        $candidates = glob($directory.DIRECTORY_SEPARATOR.'*.sk') ?: [];

        if (count($candidates) === 1) {
            return (string) $candidates[0];
        }

        throw new PluginMarketException(sprintf(
            '未指定私钥文件：请通过 --key 传入 .sk 路径，或在密钥目录 %s 中仅保留一个私钥文件。',
            $directory,
        ));
    }

    /**
     * Stable public identifier: first 8 hex chars of the public key fingerprint.
     */
    public function keyId(): string
    {
        return $this->keyId ??= substr(hash('sha256', $this->publicKey), 0, 8);
    }

    /**
     * Raw 32-byte public key.
     */
    public function publicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * Raw 64-byte secret key. Never expose this through UI or logs.
     */
    public function secretKey(): string
    {
        return $this->secretKey;
    }

    /**
     * Base64 encoded public key, suitable for registering on the market.
     */
    public function exportPublicKey(): string
    {
        return base64_encode($this->publicKey);
    }

    /**
     * Base64 encoded secret key, suitable for writing into a `.sk` file.
     */
    public function exportSecretKey(): string
    {
        return base64_encode($this->secretKey);
    }
}
