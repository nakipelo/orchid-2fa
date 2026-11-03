<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Exceptions;

use LogicException;

/**
 * The Orchid guard is not a session guard (or has no Eloquent user provider).
 */
final class UnsupportedGuardException extends LogicException {}
