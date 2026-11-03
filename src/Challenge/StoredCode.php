<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

/**
 * A code as kept in the cache: only its HMAC, never the code itself (spec §5.9).
 *
 * @internal
 */
final class StoredCode
{
    public function __construct(
        public readonly string $hash,
        public readonly string $challengeId,
        public readonly string $destinationHash,
        public readonly int $expiresAt,
    ) {}

    public function isExpired(): bool
    {
        return $this->expiresAt <= now()->getTimestamp();
    }

    /**
     * @return array{hash: string, challenge_id: string, destination_hash: string, expires_at: int}
     */
    public function toArray(): array
    {
        return [
            'hash' => $this->hash,
            'challenge_id' => $this->challengeId,
            'destination_hash' => $this->destinationHash,
            'expires_at' => $this->expiresAt,
        ];
    }

    public static function fromArray(mixed $data): ?self
    {
        if (! is_array($data)
            || ! is_string($data['hash'] ?? null)
            || ! is_string($data['challenge_id'] ?? null)
            || ! is_string($data['destination_hash'] ?? null)
            || ! is_int($data['expires_at'] ?? null)) {
            return null;
        }

        return new self($data['hash'], $data['challenge_id'], $data['destination_hash'], $data['expires_at']);
    }
}
