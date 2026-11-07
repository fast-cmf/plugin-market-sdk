<?php

namespace Openframe\PluginMarketSdk\Validation;

use RuntimeException;

class PluginMarketException extends RuntimeException
{
    /**
     * Signature-related error codes, used by SignatureVerifier so callers
     * can distinguish rejection reasons without parsing messages.
     */
    public const UNSIGNED_PACKAGE = 1001;

    public const TAMPERED_PACKAGE = 1002;

    public const UNKNOWN_KEY = 1003;

    public const REVOKED_KEY = 1004;

    public const INVALID_SIGNATURE = 1005;
}
