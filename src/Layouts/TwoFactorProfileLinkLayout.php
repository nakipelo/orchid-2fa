<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Layouts;

use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Support\Orchid;
use Orchid\Screen\Actions\Link;
use Orchid\Screen\Fields\Label;
use Orchid\Screen\Layouts\Block;
use Orchid\Screen\Repository;
use Orchid\Support\Facades\Layout;

/**
 * The entry to the two-factor profile screen for `UserProfileScreen` (spec §4.7, §6):
 * the status of the signed-in user and a link to the two-factor profile screen.
 *
 * Add one line to `layout()` of the screen: `TwoFactorProfileLinkLayout::class,`
 */
class TwoFactorProfileLinkLayout extends Block
{
    /**
     * @return mixed
     */
    public function build(Repository $repository)
    {
        $user = Orchid::guard()->user();

        if ($user === null) {
            return null;
        }

        $status = app(TwoFactorPolicy::class)->status($user);
        $channel = app(ChannelRegistry::class)->for($user);

        $this->layouts = [
            Layout::rows([
                Label::make('two_factor_status')
                    ->title(self::trans('profile.status'))
                    ->value(self::trans('status.'.$status)),

                Label::make('two_factor_method')
                    ->title(self::trans('profile.method'))
                    ->value($channel?->label() ?? '—')
                    ->canSee(in_array($status, ['required', 'enabled'], true) && $channel !== null),
            ]),
        ];

        $this
            ->title(self::trans('profile.title'))
            ->description(self::trans('profile_link.description'))
            ->commands([
                Link::make(self::trans('profile_link.manage'))
                    ->icon('bs.shield-lock')
                    ->route(Orchid::profileTwoFactorRoute()),
            ]);

        return parent::build($repository);
    }

    protected static function trans(string $key): string
    {
        return (string) __('orchid-2fa::messages.'.$key);
    }
}
