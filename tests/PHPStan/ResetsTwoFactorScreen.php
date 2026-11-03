<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Tests\PHPStan;

use Nakipelo\Orchid2FA\Concerns\ResetsTwoFactor;
use Nakipelo\Orchid2FA\Layouts\TwoFactorResetLayout;
use Orchid\Screen\Screen;

/**
 * Analysis only: PHPStan analyses a trait in the context of the classes using it, and the
 * workbench UserEditScreen stub (Orchid's own code) is not analysed.
 */
final class ResetsTwoFactorScreen extends Screen
{
    use ResetsTwoFactor;

    /**
     * @return list<class-string>
     */
    public function layout(): iterable
    {
        return [TwoFactorResetLayout::class];
    }
}
