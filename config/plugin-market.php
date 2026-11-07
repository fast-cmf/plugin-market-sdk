<?php

/*
|--------------------------------------------------------------------------
| Plugin Market SDK defaults
|--------------------------------------------------------------------------
|
| These defaults apply when the host application does not ship its own
| `config/plugin-market.php`. The `signing.mode` semantics:
|
|   strict     - unsigned or unverifiable packages are rejected.
|   permissive - signature problems are collected as warnings, but the
|                package is still accepted (internal/enterprise markets).
|   off        - signature checks are skipped entirely (local debugging).
|
| Any unknown value falls back to strict behaviour (fail closed).
|
*/

return [

    'signing' => [
        'mode' => env('PLUGIN_MARKET_SIGNING_MODE', 'permissive'),

        // key id => base64 encoded Ed25519 public key.
        'keys' => [],

        // Directory scanned for `{keyId}.pub` base64 public key files.
        'keys_path' => storage_path('app/plugin-keys'),

        // Local revocation list consumed by Signature\RevocationList.
        'revocations_path' => storage_path('app/plugin-revocations.json'),
    ],

];
