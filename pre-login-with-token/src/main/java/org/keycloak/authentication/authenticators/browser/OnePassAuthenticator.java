package org.keycloak.authentication.authenticators.browser;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.common.ClientConnection;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.onepass.OnePassProtocol;
import org.keycloak.representations.idm.OAuth2ErrorRepresentation;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;

public class OnePassAuthenticator implements Authenticator {

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        String token = authSession.getClientNote(OnePassProtocol.PROTOCOL_TOKEN_NAME);
        KeycloakSession session = context.getSession();
        RealmModel realm = session.getContext().getRealm();
        UriInfo uriInfo = session.getContext().getUri();
        ClientConnection connection = session.getContext().getConnection();
        HttpHeaders headers = session.getContext().getRequestHeaders();
        AuthenticationManager.AuthResult result = AuthenticationManager.verifyIdentityToken(
                session, realm, uriInfo, connection, true, true, false, token, headers
        );
        if (result != null) {
            context.setUser(result.getUser());
            context.success();
        } else {
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            OAuth2ErrorRepresentation errorRep = new OAuth2ErrorRepresentation(
                    "invalid_token", "token is either expired, revoked, or incorrect."
            );
            Response errorResponse = Response.status(Response.Status.UNAUTHORIZED)
                    .entity(errorRep).type(MediaType.APPLICATION_JSON_TYPE).build();
            context.failure(AuthenticationFlowError.INVALID_USER, errorResponse);
        }
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // never called
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // do nothing
    }

    @Override
    public void close() {

    }
}
