<?php

namespace Openframe\PluginMarketSdk\Signature;

use Openframe\PluginMarketSdk\Validation\PluginMarketException;
use SodiumException;
use ZipArchive;

/**
 * Three-step verification of a signed plugin package:
 *  1. developer signature over the canonical payload;
 *  2. SHA-256 digest of the package contents;
 *  3. platform endorsement, when the manifest carries one.
 *
 * Every rejection throws PluginMarketException with one of the dedicated
 * error code constants so callers can branch on the reason.
 */
final class SignatureVerifier
{
    public function __construct(
        private readonly TrustedKeyRepository $keys,
        private readonly RevocationList $revocations,
    ) {}

    /**
     * Verify the `signature.json` manifest inside an open archive.
     *
     * @param  ZipArchive  $zip  Archive already opened for reading.
     * @param  string  $packageBaseName  Basename of the zip file (informational).
     * @return array{key_id: string, endorsed: bool, sha256: string, signed_at: string}
     *
     * @throws PluginMarketException With UNSIGNED_PACKAGE / UNKNOWN_KEY /
     *                               REVOKED_KEY / INVALID_SIGNATURE / TAMPERED_PACKAGE codes.
     */
    public function verify(ZipArchive $zip, string $packageBaseName): array
    {
        $raw = $zip->getFromName(PackageSigner::signatureEntryName($zip));

        if ($raw === false) {
            throw new PluginMarketException('插件包未包含 signature.json 签名清单。', PluginMarketException::UNSIGNED_PACKAGE);
        }

        $document = json_decode($raw, true);

        if (! is_array($document)) {
            throw new PluginMarketException('signature.json 不是合法的 JSON。', PluginMarketException::INVALID_SIGNATURE);
        }

        foreach (['algorithm', 'key_id', 'package', 'sha256', 'signed_at', 'developer_signature'] as $field) {
            if (! is_string($document[$field] ?? null) || $document[$field] === '') {
                throw new PluginMarketException(sprintf('signature.json 缺少必填字段 "%s"。', $field), PluginMarketException::INVALID_SIGNATURE);
            }
        }

        if ($document['algorithm'] !== PackageSigner::ALGORITHM) {
            throw new PluginMarketException(sprintf('不支持的签名算法 "%s"。', (string) $document['algorithm']), PluginMarketException::INVALID_SIGNATURE);
        }

        $keyId = (string) $document['key_id'];

        if ($this->revocations->isRevoked('key', $keyId)) {
            throw new PluginMarketException(sprintf('签名密钥 %s 已被吊销，拒绝安装。', $keyId), PluginMarketException::REVOKED_KEY);
        }

        $publicKey = $this->keys->find($keyId);

        if ($publicKey === null) {
            throw new PluginMarketException(sprintf('未知的签名密钥 %s，无法建立信任链。', $keyId), PluginMarketException::UNKNOWN_KEY);
        }

        $payload = $this->signedPayload($document, false);

        if (! $this->verifyDetached((string) $document['developer_signature'], $payload, $publicKey)) {
            throw new PluginMarketException('开发者签名验证失败，插件包可能已被篡改。', PluginMarketException::INVALID_SIGNATURE);
        }

        if (! hash_equals(PackageSigner::hashContents($zip), (string) $document['sha256'])) {
            throw new PluginMarketException('插件包内容哈希与签名不一致，包已损坏或被篡改。', PluginMarketException::TAMPERED_PACKAGE);
        }

        return [
            'key_id' => $keyId,
            'endorsed' => $this->verifyEndorsement($document),
            'sha256' => (string) $document['sha256'],
            'signed_at' => (string) $document['signed_at'],
        ];
    }

    /**
     * Verify the optional platform endorsement block. A missing block simply
     * means "not endorsed"; an unverifiable key yields `false`, while a
     * present-but-invalid signature is treated as tampering.
     *
     * @param  array<string, mixed>  $document
     */
    private function verifyEndorsement(array $document): bool
    {
        $endorsement = $document['endorsement'] ?? null;

        if (! is_array($endorsement)) {
            return false;
        }

        foreach (['key_id', 'signature'] as $field) {
            if (! is_string($endorsement[$field] ?? null) || $endorsement[$field] === '') {
                throw new PluginMarketException(sprintf('endorsement 缺少必填字段 "%s"。', $field), PluginMarketException::INVALID_SIGNATURE);
            }
        }

        $platformKeyId = (string) $endorsement['key_id'];

        if ($this->revocations->isRevoked('key', $platformKeyId)) {
            throw new PluginMarketException(sprintf('平台背书密钥 %s 已被吊销，拒绝安装。', $platformKeyId), PluginMarketException::REVOKED_KEY);
        }

        $platformKey = $this->keys->find($platformKeyId);

        if ($platformKey === null) {
            return false;
        }

        if (! $this->verifyDetached((string) $endorsement['signature'], $this->signedPayload($document, true), $platformKey)) {
            throw new PluginMarketException('平台背书签名验证失败，插件包可能已被篡改。', PluginMarketException::INVALID_SIGNATURE);
        }

        return true;
    }

    /**
     * Canonical signed payload: the five core fields for the developer
     * signature, plus `developer_signature` for the platform endorsement
     * (the platform signs the complete developer manifest).
     *
     * @param  array<string, mixed>  $document
     */
    private function signedPayload(array $document, bool $includeDeveloperSignature): string
    {
        $payload = [
            'algorithm' => $document['algorithm'],
            'key_id' => $document['key_id'],
            'package' => $document['package'],
            'sha256' => $document['sha256'],
            'signed_at' => $document['signed_at'],
        ];

        if ($includeDeveloperSignature) {
            $payload['developer_signature'] = $document['developer_signature'];
        }

        return PackageSigner::canonicalJson($payload);
    }

    /**
     * Base64-decode and verify a detached Ed25519 signature, mapping sodium
     * failures to `false` instead of letting SodiumException bubble up.
     */
    private function verifyDetached(string $encodedSignature, string $payload, string $publicKey): bool
    {
        $signature = base64_decode($encodedSignature, true);

        if ($signature === false || strlen($signature) !== SODIUM_CRYPTO_SIGN_BYTES) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $payload, $publicKey);
        } catch (SodiumException) {
            return false;
        }
    }
}
