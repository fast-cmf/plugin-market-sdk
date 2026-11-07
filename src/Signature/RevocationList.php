<?php

namespace Openframe\PluginMarketSdk\Signature;

use Illuminate\Support\Facades\Cache;

/**
 * Revocation lookups for signing keys, backed by an optional
 * RevocationProvider and falling back to a local JSON file.
 *
 * Local file shape:
 *   {"updated_at": "...", "revoked": [{"type": "key", "value": "8f3a2c1d", "reason": "..."}]}
 *
 * Entries are cached for one day so verification stays cheap; providers
 * refresh by replacing the source and letting the cache expire.
 */
final class RevocationList
{
    private const CACHE_KEY = 'plugin-market:security:revocations';

    public function __construct(private readonly ?RevocationProvider $provider = null) {}

    /**
     * Whether the given value (e.g. a key id) appears in the revocation list.
     */
    public function isRevoked(string $type, string $value): bool
    {
        foreach ($this->entries() as $entry) {
            if (($entry['type'] ?? null) === $type && hash_equals((string) ($entry['value'] ?? ''), $value)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function entries(): array
    {
        /** @var list<array<string, mixed>> $entries */
        $entries = Cache::remember(self::CACHE_KEY, now()->addDay(), fn (): array => $this->load());

        return $entries;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function load(): array
    {
        if ($this->provider !== null) {
            return $this->provider->fetch();
        }

        return $this->loadFromLocalFile();
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function loadFromLocalFile(): array
    {
        $path = (string) config('plugin-market.signing.revocations_path', storage_path('app/plugin-revocations.json'));

        if (! is_file($path)) {
            return [];
        }

        $decoded = json_decode((string) file_get_contents($path), true);

        if (! is_array($decoded)) {
            return [];
        }

        $entries = is_array($decoded['revoked'] ?? null) ? $decoded['revoked'] : [];

        return array_values(array_filter($entries, fn ($entry): bool => is_array($entry)));
    }
}
