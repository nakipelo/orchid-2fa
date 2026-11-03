<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Exceptions;

use RuntimeException;

/**
 * A channel could not deliver the code (transport error, no destination).
 */
class DeliveryFailedException extends RuntimeException {}
