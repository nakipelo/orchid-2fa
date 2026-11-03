<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

use Illuminate\Support\Str;

/**
 * A challenge issued by a channel (spec 0.2 §4.1): for a delivery channel the code that was
 * generated and sent, for a verifier channel only an id (nothing is sent).
 *
 * The id binds the verification to this challenge: the attempts are counted per id and a
 * challenge of another channel is refused (spec 0.2 §4.4).
 */
final readonly class Challenge
{
    /**
     * @param  string  $id  random id (`Str::random(40)`)
     * @param  string  $channel  name of the channel that issued the challenge
     * @param  string  $context  why it was issued: a `TwoFactorChallengeSent::CONTEXT_*` value
     * @param  int|null  $expiresAt  Unix time the code expires (delivery); null for a verifier channel
     */
    public function __construct(
        public string $id,
        public string $channel,
        public string $context,
        public ?int $expiresAt = null,
    ) {}

    /**
     * A challenge with a new random id.
     */
    public static function make(string $channel, string $context, ?int $expiresAt = null): self
    {
        return new self(Str::random(40), $channel, $context, $expiresAt);
    }
}
