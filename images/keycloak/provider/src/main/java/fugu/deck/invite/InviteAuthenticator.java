package fugu.deck.invite;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;

/**
 * Первый вход по приглашению без почты.
 *
 * Keycloak выдаёт ссылку на регистрацию passkey только письмом. Этот шаг потока входа заменяет письмо: если запрос
 * пришёл с приглашением (заголовок X-Deck-Invite-Nick, его ставит Traefik по ответу control-plane) и у приглашённого
 * ещё НЕТ ни одного passkey, пользователь считается опознанным и уходит на обязательное действие «зарегистрировать
 * passkey». Во всех остальных случаях шаг ничего не решает, и поток идёт дальше — к обычному входу по passkey.
 * Для Windows control-plane дополнительно передаёт X-Deck-Pair-Status: pending показывает ожидание, approved —
 * обычный OAuth-вход после подписанного на телефоне pair_approve. Новое устройство всё равно остаётся pending в keyguard.
 *
 * Что это значит для безопасности:
 *  - заголовку верим только потому, что клиент его подставить не может: Traefik перезаписывает его ответом
 *    forwardAuth, а к Keycloak напрямую ходят только Traefik и сервисы кластера (NetworkPolicy);
 *  - пользователя, у которого уже есть passkey, приглашение не впускает — чужую учётную запись так не занять;
 *  - у кого нет passkey, того впускает любое действующее приглашение на его ник: это и есть первый вход.
 *    Восстановление доступа — администратор удаляет passkey и выпускает новое приглашение.
 */
public class InviteAuthenticator implements Authenticator {
    static final String HEADER = "X-Deck-Invite-Nick";
    static final String PAIR_HEADER = "X-Deck-Pair-Status";
    static final String REGISTER_PASSKEY = "webauthn-register-passwordless";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String nick = context.getHttpRequest().getHttpHeaders().getHeaderString(HEADER);
        if (nick == null || nick.isBlank()) {
            context.attempted();
            return;
        }
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), nick.trim());
        if (user == null || !user.isEnabled()) {
            context.attempted();
            return;
        }
        String pair = context.getHttpRequest().getHttpHeaders().getHeaderString(PAIR_HEADER);
        if ("invalid".equals(pair)) {
            context.form().setAttribute("pairInvalid", true);
            context.challenge(context.form().createForm("pairing-wait.ftl"));
            return;
        }
        if ("pending".equals(pair)) {
            context.challenge(context.form().createForm("pairing-wait.ftl"));
            return;
        }
        if ("approved".equals(pair)) {
            user.removeRequiredAction(REGISTER_PASSKEY);
            context.setUser(user);
            context.getEvent().user(user).detail("deck_invite", "desktop-pair");
            context.success();
            return;
        }
        boolean hasPasskey = user.credentialManager()
                .getStoredCredentialsByTypeStream(WebAuthnCredentialModel.TYPE_PASSWORDLESS)
                .findAny().isPresent();
        if (hasPasskey) {
            context.attempted();
            return;
        }
        // Без passkey вход не должен завершиться ни при каких настройках пользователя.
        user.addRequiredAction(REGISTER_PASSKEY);
        context.setUser(user);
        context.getEvent().user(user).detail("deck_invite", "first-login");
        context.success();
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        context.attempted();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    }

    @Override
    public void close() {
    }
}
