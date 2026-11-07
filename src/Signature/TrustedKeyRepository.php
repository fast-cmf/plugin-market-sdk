<?php

namespace Openframe\PluginMarketSdk\Signature;

/**
 * Resolves trusted Ed25519 public keys by key id.
 *
 * Sources, in order:
 *  1. `plugin-market.signing.keys` config map (key id => base64 public key);
 *  2. `{keyId}.pub` base64 files inside `plugin-market.signing.keys_path`.
 */
final class TrustedKeyRepository
{
    /**
     * Find the raw public key bytes for a key id, or null when unknown.
     */
    public function find(string $keyId): ?string
    {
        return $this->fromConfig($keyId) ?? $this->fromKeyStore($keyId);
    }

    private function fromConfig(string $keyId): ?string
    {
        $configured = (array) config('plugin-market.signing.keys', []);
        $encoded = $configured[$keyId] ?? null;

        if (! is_string($encoded) || $encoded === '') {
            return null;
        }

        $raw = base64_decode($encoded, true);

        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return null;
        }

        return $raw;
    }

    private function fromKeyStore(string $keyId): ?string
    {
        if (preg_match('/^[A-Fa-f0-9]{8}$/', $keyId) !== 1) {
            return null;
        }

        $path = $this->keyStorePath().DIRECTORY_SEPARATOR.$keyId.'.pub';

        if (! is_file($path)) {
            return null;
        }

        $raw = base64_decode(trim((string) file_get_contents($path)), true);

        if ($raw === false || strlen($raw) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return null;
        }

        return $raw;
    }

    private function keyStorePath(): string
    {
        return rtrim((string) config('plugin-market.signing.keys_path', storage_path('app/plugin-keys')), '/\\');
    }
}
