package org.keycloak.protocol.onepass;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AbstractLoginProtocolFactory;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.HashMap;
import java.util.Map;

public class OnePassProtocolFactory extends AbstractLoginProtocolFactory {

    @Override
    protected void createDefaultClientScopesImpl(RealmModel newRealm) {
        // do nothing
    }

    @Override
    protected void addDefaults(ClientModel client) {
        // do nothing
    }

    @Override
    public Map<String, ProtocolMapperModel> getBuiltinMappers() {
        return new HashMap<>();
    }

    @Override
    public Object createProtocolEndpoint(RealmModel realm, EventBuilder event) {
        return new OnePassService(realm, event);
    }

    @Override
    public void setupClientDefaults(ClientRepresentation rep, ClientModel newClient) {
        if (rep.getAuthenticationFlowBindingOverrides() == null) {
            AuthenticationFlowModel protocolAuthFlow = newClient.getRealm()
                    .getFlowByAlias(OnePassProtocol.PROTOCOL_AUTH_FLOW_ALIAS);
            if (protocolAuthFlow != null) {
                newClient.setAuthenticationFlowBindingOverride("browser", protocolAuthFlow.getId());
            }
        }
        // anything else ?
    }

    @Override
    public LoginProtocol create(KeycloakSession session) {
        return new OnePassProtocol().setSession(session);
    }

    @Override
    public String getId() {
        return OnePassProtocol.PROTOCOL_NAME;
    }

}
