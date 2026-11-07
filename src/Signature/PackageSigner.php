<?php

namespace Openframe\PluginMarketSdk\Signature;

use Openframe\PluginMarketSdk\Validation\PluginMarketException;
use ZipArchive;

/**
 * Signs a plugin zip by appending a `signature.json` entry.
 *
 * The digest covers every zip entry except `signature.json` itself,
 * in canonical (sorted) order including entry names — so zip metadata
 * (timestamps, compression level, entry order) never affects verification.
 */
final class PackageSigner
{
    final public const SIGNATURE_ENTRY = 'signature.json';

    final public const ALGORITHM = 'ed25519';

    /**
     * Append (or replace) the signature manifest inside the given zip.
     *
     * @param  string  $zipPath  Absolute path of the package to sign in place.
     * @param  SigningKey  $key  Developer key used for the detached signature.
     * @return array<string, string> The written signature document.
     *
     * @throws PluginMarketException When the archive cannot be opened or its layout is invalid.
     */
    public function sign(string $zipPath, SigningKey $key): array
    {
        $zip = new ZipArchive;

        if ($zip->open($zipPath) !== true) {
            throw new PluginMarketException(sprintf('无法读取插件包，签名失败：%s', $zipPath));
        }

        try {
            $signatureEntry = self::signatureEntryName($zip);
            $document = [
                'algorithm' => self::ALGORITHM,
                'key_id' => $key->keyId(),
                'package' => basename($zipPath),
                'sha256' => self::hashContents($zip),
                'signed_at' => now()->toIso8601String(),
            ];

            $document['developer_signature'] = base64_encode(
                sodium_crypto_sign_detached(self::canonicalJson($document), $key->secretKey()),
            );

            if ($zip->locateName($signatureEntry) !== false) {
                $zip->deleteName($signatureEntry);
            }

            $zip->addFromString($signatureEntry, self::canonicalJson($document)."\n");
        } finally {
            $zip->close();
        }

        return $document;
    }

    /**
     * Full zip entry path of the signature manifest: inside the single module
     * root directory (keeps the "exactly one root" package layout intact).
     */
    public static function signatureEntryName(ZipArchive $zip): string
    {
        $roots = [];

        for ($index = 0; $index < $zip->numFiles; $index++) {
            $entry = (string) $zip->getNameIndex($index);

            if ($entry === '' || str_ends_with($entry, '/')) {
                continue;
            }

            $roots[] = str_contains($entry, '/') ? (string) str($entry)->before('/') : $entry;
        }

        $roots = array_values(array_unique($roots));

        if (count($roots) !== 1) {
            throw new PluginMarketException('插件包必须只包含一个根目录（模块目录名），无法定位签名清单。');
        }

        return $roots[0].'/'.self::SIGNATURE_ENTRY;
    }

    /**
     * Canonical SHA-256 digest of the package contents (every entry except
     * the signature manifest), stable across zip repacking.
     */
    public static function hashContents(ZipArchive $zip): string
    {
        $signatureEntry = self::signatureEntryName($zip);
        $entries = [];

        for ($index = 0; $index < $zip->numFiles; $index++) {
            $entry = (string) $zip->getNameIndex($index);

            if ($entry === '' || $entry === $signatureEntry || str_ends_with($entry, '/')) {
                continue;
            }

            $entries[] = $entry;
        }

        sort($entries, SORT_STRING);

        $hash = hash_init('sha256');

        foreach ($entries as $entry) {
            hash_update($hash, $entry."\0");
            hash_update($hash, (string) $zip->getFromName($entry));
        }

        return hash_final($hash);
    }

    /**
     * Deterministic JSON encoding (recursively key-sorted) used for both the
     * signed payload and the manifest file, so signer and verifier agree byte
     * for byte.
     *
     * @param  array<string, mixed>  $data
     */
    public static function canonicalJson(array $data): string
    {
        self::sortKeysRecursive($data);

        return (string) json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    }

    /**
     * @param  array<string, mixed>  $data
     */
    private static function sortKeysRecursive(array &$data): void
    {
        ksort($data);

        foreach ($data as &$value) {
            if (is_array($value)) {
                self::sortKeysRecursive($value);
            }
        }
    }
}
