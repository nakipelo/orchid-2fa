<?php

declare(strict_types=1);

namespace Nakipelo\Orchid2FA\Screens;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Nakipelo\Orchid2FA\Challenge\Challenge;
use Nakipelo\Orchid2FA\Challenge\ChallengeManager;
use Nakipelo\Orchid2FA\Challenge\EnrollmentState;
use Nakipelo\Orchid2FA\Challenge\ProfileChallenge;
use Nakipelo\Orchid2FA\Challenge\VerificationResult;
use Nakipelo\Orchid2FA\Channels\ChannelRegistry;
use Nakipelo\Orchid2FA\Channels\DeliveryChannel;
use Nakipelo\Orchid2FA\Channels\UserMethod;
use Nakipelo\Orchid2FA\Contracts\TwoFactorChannel;
use Nakipelo\Orchid2FA\Events\RecoveryCodesRegenerated;
use Nakipelo\Orchid2FA\Events\TwoFactorChannelChanged;
use Nakipelo\Orchid2FA\Exceptions\DeliveryFailedException;
use Nakipelo\Orchid2FA\Exceptions\SendLimitExceededException;
use Nakipelo\Orchid2FA\Http\Controllers\ChallengeController;
use Nakipelo\Orchid2FA\Http\Controllers\Concerns\InteractsWithChallenge;
use Nakipelo\Orchid2FA\Policy\TwoFactorPolicy;
use Nakipelo\Orchid2FA\Recovery\RecoveryCodes;
use Nakipelo\Orchid2FA\Support\Orchid;
use Nakipelo\Orchid2FA\TwoFactorManager;
use Orchid\Screen\Actions\Button;
use Orchid\Screen\Fields\Input;
use Orchid\Screen\Fields\Label;
use Orchid\Screen\Fields\Password;
use Orchid\Screen\Screen;
use Orchid\Support\Color;
use Orchid\Support\Facades\Layout;

/**
 * Two-factor settings of the signed-in user (route `Orchid::profileTwoFactorRoute()`, spec §4.7,
 * §6; 0.2 §5.5–§5.9, §6.3).
 *
 * - Enabling (status `disabled`, or `not_enrolled`): enrollment of an allowed method; e-mail —
 *   a code to the address.
 * - Switching, rebinding, disabling and regenerating the recovery codes are confirmed with the
 *   current password and a code of the current method (or a recovery code: not for regenerating)
 *   in one form; a wrong password counts like a wrong code. The confirmation lives
 *   `profile.confirmation_ttl` and is bound to the user, the action and the target channel.
 * - An enforced user cannot disable (403 on the server).
 */
class TwoFactorProfileScreen extends Screen
{
    use InteractsWithChallenge;

    /**
     * `required`, `enabled`, `disabled` or `not_enrolled`.
     */
    public string $status = 'disabled';

    public bool $confirmed = false;

    public string $destination = '';

    public string $methodLabel = '';

    public bool $methodIsDelivery = true;

    /**
     * The action of the pending change (`enable`, `disable`, `switch`, `rebind`, `regenerate`).
     */
    public ?string $pendingAction = null;

    /**
     * The step of the pending change (`confirm_current`, `enroll`).
     */
    public ?string $pendingStep = null;

    public int $codeLength = 6;

    public string $codePattern = '\d{6}';

    public bool $stepIsDelivery = true;

    public string $stepPrompt = '';

    public ?string $enrollmentView = null;

    /**
     * @var array<string, mixed>
     */
    public array $enrollmentData = [];

    public string $stepLabel = '';

    /**
     * Allowed channels to enable (status disabled / not_enrolled) or to switch to: name => label.
     *
     * @var array<string, string>
     */
    public array $choices = [];

    public bool $canRebind = false;

    public bool $hasRecoveryCodes = false;

    public int $recoveryRemaining = 0;

    public bool $recoveryWarning = false;

    /**
     * @var list<string>|null
     */
    public ?array $shownCodes = null;

    public bool $recoveryLogin = false;

    public bool $recoveryAllowed = false;

    /**
     * @return array<string, mixed>
     */
    public function query(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, RecoveryCodes $recovery): iterable
    {
        $user = $this->currentUser();
        $status = $policy->status($user);
        $method = $channels->methodFor($user);
        $current = $method->channel;
        $pending = $this->pendingFor($request, $policy, $channels, $user, $status);
        $step = $this->stepChannel($pending, $current, $channels);
        $input = ($step ?? $current)?->codeInput();
        $state = $pending?->step === ProfileChallenge::STEP_ENROLL && $step !== null
            ? EnrollmentState::fromSession($request->session(), $user, $step->name(), $pending->action, $this->confirmationTtl())
            : null;
        $hasCodes = $current !== null && $current->needsRecoveryCodes() && $status !== 'disabled';
        $remaining = $hasCodes ? $recovery->remaining($user) : 0;
        $active = $status !== 'disabled' && $status !== 'not_enrolled';

        return [
            'status' => $status,
            'confirmed' => $policy->isConfirmed($user),
            'destination' => $current instanceof DeliveryChannel ? $current->maskedDestination($user) : '',
            'methodLabel' => $current?->label() ?? '',
            'methodIsDelivery' => $current === null || $current->requiresDelivery(),
            'pendingAction' => $pending?->action,
            'pendingStep' => $pending?->step,
            'codeLength' => $input->length ?? 6,
            'codePattern' => $input->pattern ?? '\d{6}',
            'stepIsDelivery' => $step === null || $step->requiresDelivery(),
            'stepPrompt' => $step !== null ? $step->prompt($user) : '',
            'stepLabel' => $step?->label() ?? '',
            'enrollmentView' => $state !== null ? $step->enrollmentView() : null,
            'enrollmentData' => $state !== null ? $step->enrollmentData($user, $state) : [],
            'choices' => $this->choicesFor($channels, $active ? $current : null, ! $active),
            'canRebind' => $active && $method->state === UserMethod::ACTIVE && $current?->enrollmentView() !== null,
            'hasRecoveryCodes' => $hasCodes,
            'recoveryRemaining' => $remaining,
            'recoveryWarning' => $hasCodes && $remaining <= $recovery->warnAt(),
            'shownCodes' => RecoveryCodes::forDisplay($request->session(), $user),
            'recoveryLogin' => (bool) $request->session()->get(ChallengeController::RECOVERY_LOGIN, false),
            'recoveryAllowed' => $current !== null && $current->needsRecoveryCodes()
                && in_array($pending?->action, [ProfileChallenge::SWITCH, ProfileChallenge::REBIND, ProfileChallenge::DISABLE], true),
        ];
    }

    public function name(): ?string
    {
        return $this->trans('profile.title');
    }

    public function description(): ?string
    {
        return $this->trans('profile.description');
    }

    /**
     * @return iterable<mixed>
     */
    public function layout(): iterable
    {
        $action = $this->pendingAction;
        $confirming = $this->pendingStep === ProfileChallenge::STEP_CONFIRM_CURRENT;
        $enrolling = $this->pendingStep === ProfileChallenge::STEP_ENROLL;
        $idle = $action === null;
        $active = in_array($this->status, ['required', 'enabled'], true);

        return [
            Layout::rows([
                Label::make('two_factor_recovery_login')
                    ->value($this->trans('profile.recovery_login', ['count' => $this->recoveryRemaining])),
            ])->canSee($this->recoveryLogin && $this->hasRecoveryCodes),

            Layout::block(Layout::rows([
                Label::make('two_factor_status')
                    ->title($this->trans('profile.status'))
                    ->value($this->trans('status.'.$this->status)),

                Label::make('two_factor_method')
                    ->title($this->trans('profile.method'))
                    ->value($this->methodLabel)
                    ->canSee($active && $this->methodLabel !== ''),

                Label::make('two_factor_destination')
                    ->title($this->trans('profile.destination'))
                    ->value($this->destinationText())
                    ->canSee($this->methodIsDelivery && $this->status !== 'not_enrolled'),
            ]))
                ->title($this->trans('profile.status_title'))
                ->description($this->trans('profile.status_description.'.$this->status))
                ->commands([...$this->enableButtons($idle), ...$this->switchButtons($idle && $active), ...[
                    Button::make($this->trans('profile.rebind'))
                        ->icon('bs.arrow-repeat')
                        ->novalidate()
                        ->method('startRebind')
                        ->canSee($idle && $this->canRebind),

                    Button::make($this->trans('profile.disable'))
                        ->icon('bs.shield-x')
                        ->type(Color::DANGER)
                        ->novalidate()
                        ->method('sendDisableCode')
                        ->canSee($this->status === 'enabled' && $idle),
                ]]),

            Layout::block(Layout::rows([
                Password::make('password')
                    ->title($this->trans('profile.password'))
                    ->autocomplete('current-password')
                    ->required(),

                Input::make('code')
                    ->title($this->trans('challenge.code'))
                    ->help($this->stepIsDelivery ? $this->trans('challenge.sent_to', ['destination' => $this->destination]) : $this->stepPrompt)
                    ->autocomplete('one-time-code')
                    ->inputmode('numeric')
                    ->pattern($this->codePattern)
                    ->maxlength($this->codeLength),

                Input::make('recovery_code')
                    ->title($this->trans('recovery.use'))
                    ->help($this->trans('profile.recovery_code_help'))
                    ->autocomplete('off')
                    ->maxlength(64)
                    ->canSee($this->recoveryAllowed),
            ]))
                ->title($this->trans('profile.confirm_'.($action ?? 'disable')))
                ->description($this->trans('profile.confirm_current_description'))
                ->commands([
                    Button::make($this->trans('profile.cancel'))
                        ->novalidate()
                        ->method('cancelCode'),

                    Button::make($this->trans('challenge.resend'))
                        ->novalidate()
                        ->method($action === ProfileChallenge::DISABLE ? 'sendDisableCode' : 'sendConfirmCode')
                        ->canSee($this->stepIsDelivery),

                    Button::make($this->trans('profile.confirm'))
                        ->icon('bs.check-circle')
                        ->type(Color::PRIMARY)
                        ->method($action === ProfileChallenge::DISABLE ? 'disable' : 'confirmCurrent'),
                ])
                ->canSee($confirming),

            Layout::view($this->enrollmentView ?? 'orchid-2fa::partials.empty', $this->enrollmentData)
                ->canSee($enrolling && $this->enrollmentView !== null),

            Layout::block(Layout::rows([
                Input::make('code')
                    ->title($this->trans('challenge.code'))
                    ->help($this->stepIsDelivery ? $this->stepPrompt : $this->trans('profile.enroll_code_help', ['method' => $this->stepLabel]))
                    ->autocomplete('one-time-code')
                    ->inputmode('numeric')
                    ->pattern($this->codePattern)
                    ->maxlength($this->codeLength)
                    ->required(),
            ]))
                ->title($action === ProfileChallenge::ENABLE ? $this->trans('profile.confirm_enable') : $this->trans('profile.enroll_title', ['method' => $this->stepLabel]))
                ->description($this->trans($this->stepIsDelivery ? 'profile.confirm_description' : 'profile.enroll_description'))
                ->commands([
                    Button::make($this->trans('profile.cancel'))
                        ->novalidate()
                        ->method('cancelCode'),

                    Button::make($this->trans('challenge.resend'))
                        ->novalidate()
                        ->method($action === ProfileChallenge::ENABLE ? 'sendEnableCode' : 'sendConfirmCode')
                        ->canSee($this->stepIsDelivery),

                    Button::make($this->trans('profile.confirm'))
                        ->icon('bs.check-circle')
                        ->type(Color::PRIMARY)
                        ->method($action === ProfileChallenge::ENABLE ? 'enable' : 'confirmEnrollment'),
                ])
                ->canSee($enrolling),

            Layout::block(Layout::view('orchid-2fa::partials.recovery-codes', ['codes' => $this->shownCodes ?? []]))
                ->title($this->trans('recovery.title'))
                ->description($this->trans('recovery.once'))
                ->commands([
                    Button::make($this->trans('recovery.saved'))
                        ->icon('bs.check-circle')
                        ->type(Color::PRIMARY)
                        ->novalidate()
                        ->method('acknowledgeRecoveryCodes'),
                ])
                ->canSee($this->shownCodes !== null),

            Layout::block(Layout::rows([
                Label::make('two_factor_recovery_remaining')
                    ->value($this->trans($this->recoveryWarning ? 'profile.recovery_warning' : 'profile.recovery_remaining', ['count' => $this->recoveryRemaining])),
            ]))
                ->title($this->trans('recovery.title'))
                ->description($this->trans('profile.recovery_description'))
                ->commands([
                    Button::make($this->trans('profile.regenerate'))
                        ->icon('bs.arrow-clockwise')
                        ->novalidate()
                        ->method('startRegenerate')
                        ->canSee($idle),
                ])
                ->canSee($this->hasRecoveryCodes && $this->shownCodes === null),

            Layout::block(Layout::rows([
                Label::make('trusted_devices')
                    ->value($this->trans('profile.trusted_text')),
            ]))
                ->title($this->trans('profile.trusted_title'))
                ->description($this->trans('profile.trusted_description'))
                ->commands([
                    Button::make($this->trans('profile.trusted_forget'))
                        ->icon('bs.box-arrow-right')
                        ->novalidate()
                        ->confirm($this->trans('profile.trusted_confirm'))
                        ->method('forgetTrustedDevices'),
                ]),
        ];
    }

    /**
     * "Enable" (spec §4.7, 0.2 §5.5): enrollment of the only allowed method, or of `channel`.
     * A delivery method gets a code at the address; calling it again sends a new one.
     */
    public function sendEnableCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $this->startEnable($request, $policy, $challenges, $channels, $request->input('channel'));
    }

    /**
     * "Enable" with the choice of the method (spec 0.2 §5.5 item 1).
     */
    public function chooseChannel(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $this->startEnable($request, $policy, $challenges, $channels, $request->input('channel'));
    }

    /**
     * Confirm the enabling with the first code (spec 0.2 §5.5 item 3).
     *
     * @throws ValidationException
     */
    public function enable(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, TwoFactorManager $manager): void
    {
        $this->finishEnrollment($request, $policy, $challenges, $channels, $manager, ProfileChallenge::ENABLE);
    }

    /**
     * Confirm the enrollment of the target channel of a switch or rebind.
     *
     * @throws ValidationException
     */
    public function confirmEnrollment(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, TwoFactorManager $manager): void
    {
        $user = $this->currentUser();
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        $this->finishEnrollment($request, $policy, $challenges, $channels, $manager, $pending->action ?? ProfileChallenge::SWITCH);
    }

    /**
     * "Disable": a code of the current method (sent for a delivery one); refused for an enforced user.
     */
    public function sendDisableCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $this->startConfirmation($request, $policy, $challenges, $channels, ProfileChallenge::DISABLE, null);
    }

    /**
     * @throws ValidationException
     */
    public function disable(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, TwoFactorManager $manager): void
    {
        $user = $this->confirmWithCurrentMethod($request, $policy, $challenges, $channels, ProfileChallenge::DISABLE);

        if ($user !== null) {
            ProfileChallenge::forget($request->session());
            $manager->disable($user);
            Orchid::toast($this->trans('profile.disabled'), 'success');
        }
    }

    /**
     * "Change the method" to `channel` (spec 0.2 §5.6).
     */
    public function startSwitch(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $target = $request->input('channel');

        $this->startConfirmation($request, $policy, $challenges, $channels, ProfileChallenge::SWITCH, is_string($target) && $target !== '' ? $target : '-');
    }

    /**
     * "Rebind" the current method, e.g. a new phone (spec 0.2 §5.7).
     */
    public function startRebind(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $current = $channels->for($this->currentUser());

        $this->startConfirmation($request, $policy, $challenges, $channels, ProfileChallenge::REBIND, $current?->name() ?? '-');
    }

    /**
     * "Regenerate the recovery codes" (spec 0.2 §5.9).
     */
    public function startRegenerate(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $this->startConfirmation($request, $policy, $challenges, $channels, ProfileChallenge::REGENERATE, null);
    }

    /**
     * "Send again" of the confirmation or of the enrollment step of a delivery channel.
     */
    public function sendConfirmCode(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels): void
    {
        $user = $this->currentUser();
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        if ($pending === null) {
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return;
        }

        if ($pending->step === ProfileChallenge::STEP_CONFIRM_CURRENT) {
            $this->startConfirmation($request, $policy, $challenges, $channels, $pending->action, $pending->target);

            return;
        }

        if ($pending->step === ProfileChallenge::STEP_ENROLL && $pending->target !== null && $this->authorizeAction($request, $policy, $channels, $user, $pending->action, $pending->target)) {
            $target = $channels->channel($pending->target);
            $state = EnrollmentState::fromSession($request->session(), $user, $target->name(), $pending->action, $this->confirmationTtl())
                ?? EnrollmentState::start($request->session(), $user, $target->name(), $pending->action);

            $this->startStep($user, $challenges, $target, $state);
        }
    }

    /**
     * Confirm a switch, rebind or regeneration with the password and a code of the current method.
     *
     * @throws ValidationException
     */
    public function confirmCurrent(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, RecoveryCodes $recovery): void
    {
        $user = $this->currentUser();
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());
        $action = $pending->action ?? ProfileChallenge::SWITCH;

        if ($action === ProfileChallenge::ENABLE) {
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return;
        }

        if ($action === ProfileChallenge::DISABLE) {
            $this->disable($request, $policy, $challenges, $channels, app(TwoFactorManager::class));

            return;
        }

        $user = $this->confirmWithCurrentMethod($request, $policy, $challenges, $channels, $action);

        if ($user === null || $pending === null) {
            return;
        }

        if ($action === ProfileChallenge::REGENERATE) {
            ProfileChallenge::forget($request->session());

            $codes = $recovery->generate($user);
            RecoveryCodes::keepForDisplay($request->session(), $user, $codes);
            $current = $channels->for($user);
            app('events')->dispatch(new RecoveryCodesRegenerated($user, Orchid::guardName(), $current?->name() ?? '', count($codes)));

            Orchid::toast($this->trans('profile.regenerated'), 'success');

            return;
        }

        $target = $channels->channel((string) $pending->target);
        $state = EnrollmentState::start($request->session(), $user, $target->name(), $action);

        $pending->withStep(ProfileChallenge::STEP_ENROLL, $state->challengeId(), $target->name(), now()->getTimestamp())
            ->store($request->session());

        $this->startStep($user, $challenges, $target, $state);
    }

    /**
     * "I have saved the codes".
     */
    public function acknowledgeRecoveryCodes(Request $request): void
    {
        RecoveryCodes::forgetDisplay($request->session());
    }

    /**
     * Drop the pending change. A sent code is not deleted (like "sign in as a different user").
     */
    public function cancelCode(Request $request): void
    {
        ProfileChallenge::forget($request->session());
        EnrollmentState::forget($request->session());
    }

    /**
     * "Sign out of all trusted devices": available with any status (spec §4.7).
     */
    public function forgetTrustedDevices(TwoFactorManager $manager): void
    {
        $manager->forgetTrustedDevices($this->currentUser());

        Orchid::toast($this->trans('profile.trusted_forgotten'), 'success');
    }

    protected function startEnable(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, mixed $name): void
    {
        $user = $this->currentUser();
        $allowed = $channels->allowed();
        $method = $channels->methodFor($user);

        // Without a choice: the user's own allowed method, the only allowed one, the default one.
        $name = match (true) {
            is_string($name) && $name !== '' => $name,
            $method->state === UserMethod::ACTIVE && $method->channel !== null => $method->channel->name(),
            count($allowed) === 1 => $allowed[0],
            default => $channels->defaultName(),
        };

        if (! $this->authorizeAction($request, $policy, $channels, $user, ProfileChallenge::ENABLE, $name)) {
            return;
        }

        $target = $channels->channel($name);
        $state = EnrollmentState::start($request->session(), $user, $name, ProfileChallenge::ENABLE);

        (new ProfileChallenge($user->getAuthIdentifier(), ProfileChallenge::ENABLE, $state->challengeId(), $name, $name, ProfileChallenge::STEP_ENROLL))
            ->store($request->session());

        if (! $this->startStep($user, $challenges, $target, $state)) {
            ProfileChallenge::forget($request->session());
            EnrollmentState::forget($request->session());
        }
    }

    /**
     * Start the enrollment step of the target channel; false when its code could not be sent.
     */
    protected function startStep(Authenticatable $user, ChallengeManager $challenges, TwoFactorChannel $target, EnrollmentState $state): bool
    {
        try {
            $challenges->startEnrollment($user, $target, $state);
        } catch (SendLimitExceededException $e) {
            Orchid::toast($this->sendLimitMessage($e->availableIn), 'warning');

            return false;
        } catch (DeliveryFailedException) {
            Orchid::toast($this->trans('errors.delivery_failed'), 'error');

            return false;
        }

        Orchid::toast($target instanceof DeliveryChannel
            ? $this->trans('profile.code_sent', ['destination' => $target->maskedDestination($user)])
            : $this->trans('profile.enroll_started', ['method' => $target->label()]));

        return true;
    }

    /**
     * Ask for the confirmation with the current method: a delivery method gets a code with the
     * context of the action, a verifier one only a new challenge.
     *
     * @param  ProfileChallenge::DISABLE|ProfileChallenge::SWITCH|ProfileChallenge::REBIND|ProfileChallenge::REGENERATE|string  $action
     */
    protected function startConfirmation(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, string $action, ?string $target): void
    {
        $user = $this->currentUser();

        if (! $this->authorizeAction($request, $policy, $channels, $user, $action, $target)) {
            return;
        }

        $channel = $challenges->channelFor($user);

        try {
            $challenge = $challenges->issue($user, $action, $channel);
        } catch (SendLimitExceededException $e) {
            Orchid::toast($this->sendLimitMessage($e->availableIn), 'warning');

            return;
        } catch (DeliveryFailedException) {
            Orchid::toast($this->trans('errors.delivery_failed'), 'error');

            return;
        }

        /** @var ProfileChallenge::DISABLE|ProfileChallenge::SWITCH|ProfileChallenge::REBIND|ProfileChallenge::REGENERATE $action */
        (new ProfileChallenge($user->getAuthIdentifier(), $action, $challenge->id, $challenge->channel, $target))->store($request->session());
        EnrollmentState::forget($request->session());

        Orchid::toast($channel instanceof DeliveryChannel
            ? $this->trans('profile.code_sent', ['destination' => $channel->maskedDestination($user)])
            : $this->trans('profile.enter_current_code', ['method' => $channel->label()]));
    }

    /**
     * The user, when the password and the code (or a recovery code where allowed) of the pending
     * confirmation are correct; null otherwise (with a toast). A wrong password or code throws a
     * validation error; a wrong password counts like a wrong code (spec 0.2 §5.6 item 6).
     *
     * @throws ValidationException
     */
    protected function confirmWithCurrentMethod(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, string $action): ?Authenticatable
    {
        $user = $this->currentUser();
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        if (! $this->authorizeAction($request, $policy, $channels, $user, $action, $pending?->target)) {
            return null;
        }

        if ($pending === null || $pending->action !== $action || $pending->step !== ProfileChallenge::STEP_CONFIRM_CURRENT) {
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return null;
        }

        $recoveryAllowed = $action !== ProfileChallenge::REGENERATE;
        $useRecovery = $recoveryAllowed && is_string($request->input('recovery_code')) && trim((string) $request->input('recovery_code')) !== '';

        $request->validate([
            'password' => 'required|string|max:1024',
            'code' => ($useRecovery ? 'nullable' : 'required').'|string|max:64',
            'recovery_code' => 'nullable|string|max:64',
        ]);

        $channel = $channels->for($user);
        $userCounters = $useRecovery || ($channel !== null && ! $channel->requiresDelivery());
        $challenge = $pending->challenge();

        if (! Orchid::guard()->getProvider()->validateCredentials($user, ['password' => (string) $request->input('password')])) {
            $result = $challenges->rejectAttempt($user, $challenge, $userCounters);

            return $this->refused($request, $challenges, $user, $challenge, $result, 'password', $userCounters);
        }

        $result = $useRecovery
            ? $challenges->verifyRecoveryCode($user, $challenge, (string) $request->input('recovery_code'))
            : $challenges->verify($user, $challenge, (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            return $this->refused($request, $challenges, $user, $challenge, $result, $useRecovery ? 'recovery_code' : 'code', $userCounters);
        }

        return $user;
    }

    /**
     * @throws ValidationException
     */
    protected function refused(Request $request, ChallengeManager $challenges, Authenticatable $user, Challenge $challenge, VerificationResult $result, string $field, bool $userCounters): null
    {
        $userLockout = $this->userLockoutMessage($challenges->lockout());

        if ($userLockout !== null) {
            throw ValidationException::withMessages([$field => $userLockout]);
        }

        if ($result === VerificationResult::Invalid) {
            $left = $challenges->attemptsLeft($user, $challenge, $userCounters);

            throw ValidationException::withMessages([$field => match ($field) {
                'password' => $this->trans('errors.invalid_password', ['attempts' => $left]),
                'recovery_code' => $this->trans('errors.invalid_recovery_code', ['attempts' => $left]),
                default => $this->trans('errors.invalid_code', ['attempts' => $left]),
            }]);
        }

        ProfileChallenge::forget($request->session());
        EnrollmentState::forget($request->session());
        Orchid::toast($this->trans('errors.code_expired'), 'error');

        return null;
    }

    /**
     * @throws ValidationException
     */
    protected function finishEnrollment(Request $request, TwoFactorPolicy $policy, ChallengeManager $challenges, ChannelRegistry $channels, TwoFactorManager $manager, string $action): void
    {
        $user = $this->currentUser();
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        if (! $this->authorizeAction($request, $policy, $channels, $user, $action, $pending?->target)) {
            return;
        }

        $state = $pending !== null && $pending->target !== null
            ? EnrollmentState::fromSession($request->session(), $user, $pending->target, $action, $this->confirmationTtl())
            : null;

        if ($pending === null || $pending->action !== $action || $pending->step !== ProfileChallenge::STEP_ENROLL || $state === null
            || ($action !== ProfileChallenge::ENABLE && ! $pending->isConfirmed($this->confirmationTtl()))) {
            ProfileChallenge::forget($request->session());
            EnrollmentState::forget($request->session());
            Orchid::toast($this->trans('errors.code_expired'), 'error');

            return;
        }

        $request->validate(['code' => 'required|string|max:64']);

        $target = $channels->channel($state->channel);
        $result = $challenges->confirmEnrollment($user, $target, $state, (string) $request->input('code'));

        if ($result !== VerificationResult::Passed) {
            $this->refused($request, $challenges, $user, $challenges->enrollmentChallenge($target, $state), $result, 'code', ! $target->requiresDelivery());

            return;
        }

        ProfileChallenge::forget($request->session());
        EnrollmentState::forget($request->session());

        $codes = $manager->commitEnrollment($user, $target, match ($action) {
            ProfileChallenge::SWITCH => TwoFactorChannelChanged::SWITCHED,
            ProfileChallenge::REBIND => TwoFactorChannelChanged::REBOUND,
            default => TwoFactorChannelChanged::ENROLLED,
        }, $action === ProfileChallenge::ENABLE && $policy->status($user) === 'disabled');

        if ($codes !== null) {
            RecoveryCodes::keepForDisplay($request->session(), $user, $codes);
        }

        Orchid::toast($this->trans(match ($action) {
            ProfileChallenge::SWITCH => 'profile.switched',
            ProfileChallenge::REBIND => 'profile.rebound',
            default => 'profile.enabled',
        }, ['method' => $target->label()]), 'success');
    }

    /**
     * Who may do what (spec §4.7, 0.2 §5.5–§5.9). An enforced user is refused with 403 for
     * enabling and disabling; otherwise a stale or impossible request only gets a toast.
     */
    protected function authorizeAction(Request $request, TwoFactorPolicy $policy, ChannelRegistry $channels, Authenticatable $user, string $action, ?string $target): bool
    {
        $status = $policy->status($user);
        $method = $channels->methodFor($user);
        $current = $method->channel;
        $active = $status === 'required' || $status === 'enabled';

        if ($status === 'required' && ($action === ProfileChallenge::ENABLE || $action === ProfileChallenge::DISABLE)) {
            $this->forgetPending($request);

            abort(403, $this->trans('profile.enforced'));
        }

        $allowed = match ($action) {
            ProfileChallenge::ENABLE => in_array($status, ['disabled', 'not_enrolled'], true) && ($target === null || $channels->isAllowed($target)),
            ProfileChallenge::DISABLE => $status === 'enabled',
            // A missing target (no pending change) is refused later as an expired confirmation.
            ProfileChallenge::SWITCH => $active && $current !== null && ($target === null || ($target !== $current->name() && $channels->isAllowed($target))),
            ProfileChallenge::REBIND => $active && $method->state === UserMethod::ACTIVE && $current !== null && $current->enrollmentView() !== null
                && ($target === null || $target === $current->name()),
            ProfileChallenge::REGENERATE => $active && $current !== null && $current->needsRecoveryCodes(),
            default => false,
        };

        if ($allowed) {
            return true;
        }

        $this->forgetPending($request);
        Orchid::toast($this->trans(match (true) {
            $action === ProfileChallenge::ENABLE && $active => 'profile.already_enabled',
            $action === ProfileChallenge::ENABLE => 'profile.method_not_allowed',
            $action === ProfileChallenge::DISABLE || ! $active => 'profile.not_enabled',
            default => 'profile.method_not_allowed',
        }), 'warning');

        return false;
    }

    protected function forgetPending(Request $request): void
    {
        ProfileChallenge::forget($request->session());
        EnrollmentState::forget($request->session());
    }

    /**
     * The pending change of the user, when it still fits the status.
     */
    protected function pendingFor(Request $request, TwoFactorPolicy $policy, ChannelRegistry $channels, Authenticatable $user, string $status): ?ProfileChallenge
    {
        $pending = ProfileChallenge::fromSession($request->session(), $user->getAuthIdentifier());

        if ($pending === null) {
            return null;
        }

        $fits = match ($pending->action) {
            ProfileChallenge::ENABLE => in_array($status, ['disabled', 'not_enrolled'], true),
            ProfileChallenge::DISABLE => $status === 'enabled',
            default => in_array($status, ['required', 'enabled'], true),
        };

        return $fits ? $pending : null;
    }

    /**
     * The channel whose code the pending step asks for.
     */
    protected function stepChannel(?ProfileChallenge $pending, ?TwoFactorChannel $current, ChannelRegistry $channels): ?TwoFactorChannel
    {
        if ($pending === null) {
            return null;
        }

        try {
            return $channels->has($pending->channel) ? $channels->channel($pending->channel) : $current;
        } catch (\InvalidArgumentException) {
            return $current;
        }
    }

    /**
     * @return array<string, string>
     */
    protected function choicesFor(ChannelRegistry $channels, ?TwoFactorChannel $current, bool $enabling): array
    {
        if (! $enabling && $current === null) {
            return [];
        }

        $choices = [];

        foreach ($channels->allowed() as $name) {
            if ($current !== null && $name === $current->name()) {
                continue;
            }

            $choices[$name] = $channels->channel($name)->label();
        }

        return $choices;
    }

    /**
     * @return list<Button>
     */
    protected function enableButtons(bool $idle): array
    {
        if (! $idle || ! in_array($this->status, ['disabled', 'not_enrolled'], true) || $this->choices === []) {
            return [];
        }

        if (count($this->choices) === 1) {
            return [
                Button::make($this->trans('profile.enable'))
                    ->icon('bs.shield-check')
                    ->type(Color::PRIMARY)
                    ->novalidate()
                    ->method('sendEnableCode', ['channel' => array_key_first($this->choices)]),
            ];
        }

        $buttons = [];

        foreach ($this->choices as $name => $label) {
            $buttons[] = Button::make($this->trans('profile.enable_with', ['method' => $label]))
                ->icon('bs.shield-check')
                ->novalidate()
                ->method('chooseChannel', ['channel' => $name]);
        }

        return $buttons;
    }

    /**
     * @return list<Button>
     */
    protected function switchButtons(bool $visible): array
    {
        if (! $visible) {
            return [];
        }

        $buttons = [];

        foreach ($this->choices as $name => $label) {
            $buttons[] = Button::make($this->trans('profile.switch_to', ['method' => $label]))
                ->icon('bs.arrow-left-right')
                ->novalidate()
                ->method('startSwitch', ['channel' => $name]);
        }

        return $buttons;
    }

    protected function destinationText(): string
    {
        if ($this->status === 'disabled') {
            return $this->destination;
        }

        return $this->trans($this->confirmed ? 'profile.confirmed' : 'profile.unconfirmed', [
            'destination' => $this->destination,
        ]);
    }

    protected function confirmationTtl(): int
    {
        return max(1, (int) config('orchid-2fa.profile.confirmation_ttl', 600));
    }

    protected function currentUser(): Authenticatable
    {
        $user = Orchid::guard()->user();

        abort_if($user === null, 403);

        return $user;
    }
}
