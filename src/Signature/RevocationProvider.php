<?php

namespace Openframe\PluginMarketSdk\Signature;

/**
 * Contract for remote revocation sources (e.g. the market platform's
 * `GET /api/security/revocations` endpoint). Phase 1 only ships the local
 * JSON file implementation; HTTP providers can be bound later without
 * touching the verifier.
 */
interface RevocationProvider
{
    /**
     * Fetch the current revocation entries.
     *
     * @return list<array{type: string, value: string, reason?: string}>
     */
    public function fetch(): array;
}
