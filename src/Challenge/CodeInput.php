<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Challenge;

/**
 * Attributes of the code field a channel asks for (spec 0.2 §4.1, §6.1).
 */
final readonly class CodeInput
{
    /**
     * @param  int  $length  expected length (also the `maxlength` of the field)
     * @param  string  $pattern  HTML `pattern` of the field, without anchors
     * @param  string  $inputmode  HTML `inputmode`
     * @param  string  $autocomplete  HTML `autocomplete`
     */
    public function __construct(
        public int $length,
        public string $pattern,
        public string $inputmode = 'numeric',
        public string $autocomplete = 'one-time-code',
    ) {}

    /**
     * A field for a code of the given number of digits.
     */
    public static function digits(int $length): self
    {
        $length = max(1, $length);

        return new self($length, '\d{'.$length.'}');
    }
}
