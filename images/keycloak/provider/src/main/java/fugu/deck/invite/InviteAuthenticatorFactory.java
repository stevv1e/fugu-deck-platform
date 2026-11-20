package fugu.deck.invite;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class InviteAuthenticatorFactory implements AuthenticatorFactory {
    public static final String ID = "deck-invite";
    private static final InviteAuthenticator INSTANCE = new InviteAuthenticator();
    private static final Requirement[] REQUIREMENTS = {Requirement.ALTERNATIVE, Requirement.DISABLED};

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayType() {
        return "Fugu Deck: first login by invite";
    }

    @Override
    public String getReferenceCategory() {
        return "invite";
    }

    @Override
    public String getHelpText() {
        return "Lets an invited user without a passkey in to register one. Trusts the X-Deck-Invite-Nick header set by the edge proxy.";
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public Requirement[] getRequirementChoices() {
        return REQUIREMENTS;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return List.of();
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return INSTANCE;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }
}
