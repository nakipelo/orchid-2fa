<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Layouts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use Orchid\Screen\Actions\Button;
use Orchid\Screen\Fields\Label;
use Orchid\Screen\Layouts\Block;
use Orchid\Screen\Repository;
use Orchid\Support\Color;
use Orchid\Support\Facades\Layout;

/**
 * "Reset 2FA" for `UserEditScreen` (spec §4.8, §6): the two-factor status of the edited user
 * (`user` of the screen query) and the reset button. Shown only to holders of the
 * reset permission (`Orchid::resetPermission()`, spec §8) and for an existing user.
 *
 * Two lines in the screen: `use ResetsTwoFactor;` and `TwoFactorResetLayout::class,` in `layout()`.
 */
class TwoFactorResetLayout extends Block
{
    /**
     * @return mixed
     */
    public function build(Repository $repository)
    {
        $user = $repository->get('user');
        $admin = Orchid::guard()->user();

        if (! $user instanceof Authenticatable
            || ($user instanceof Model && ! $user->exists)
            || $admin === null
            || ! Orchid::userHasPermission($admin, Orchid::resetPermission())) {
            return null;
        }

        $policy = app(TwoFactorPolicy::class);
        $status = $policy->status($user);
        // The channel of the user, not the default one (spec 0.2 §4.5, §6.3); a mask only for delivery.
        $channel = app(ChannelRegistry::class)->for($user);
        $destination = $channel instanceof DeliveryChannel ? $channel->maskedDestination($user) : '';

        $this->layouts = [
            Layout::rows([
                Label::make('two_factor_status')
                    ->title(self::trans('profile.status'))
                    ->value(self::trans('reset.status.'.$status)),

                Label::make('two_factor_destination')
                    ->title(self::trans('profile.destination'))
                    ->value(self::trans($policy->isConfirmed($user) ? 'profile.confirmed' : 'profile.unconfirmed', [
                        'destination' => $destination,
                    ])),
            ]),
        ];

        $this
            ->title(self::trans('profile.title'))
            ->description(self::trans('reset.description'))
            ->commands([
                Button::make(self::trans('reset.button'))
                    ->icon('bs.shield-x')
                    ->type(Color::DANGER)
                    ->novalidate()
                    ->confirm(self::trans('reset.confirm'))
                    ->method('resetTwoFactor'),
            ]);

        return parent::build($repository);
    }

    /**
     * @param  array<string, string>  $replace
     */
    protected static function trans(string $key, array $replace = []): string
    {
        return (string) __('orchid-2fa::messages.'.$key, $replace);
    }
}
