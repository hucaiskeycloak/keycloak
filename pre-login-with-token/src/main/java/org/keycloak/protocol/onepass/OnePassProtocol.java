package org.keycloak.protocol.onepass;

import org.keycloak.events.EventBuilder;
import org.keycloak.models.AuthenticatedClientSessionModel;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.protocol.LoginProtocol;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriInfo;
import java.net.URI;

public class OnePassProtocol implements LoginProtocol {

    public static final String PROTOCOL_NAME = "one-pass";
    public static final String PROTOCOL_AUTH_FLOW_ALIAS = "One Pass";
    public static final String PROTOCOL_TOKEN_NAME = "one-pass.token";

    private KeycloakSession session;
    private RealmModel realm;
    private UriInfo uriInfo;
    private HttpHeaders headers;
    private EventBuilder event;

    @Override
    public OnePassProtocol setSession(KeycloakSession session) {
        this.session = session;
        return this;
    }

    @Override
    public OnePassProtocol setRealm(RealmModel realm) {
        this.realm = realm;
        return this;
    }

    @Override
    public OnePassProtocol setUriInfo(UriInfo uriInfo) {
        this.uriInfo = uriInfo;
        return this;
    }

    @Override
    public OnePassProtocol setHttpHeaders(HttpHeaders headers) {
        this.headers = headers;
        return this;
    }

    @Override
    public OnePassProtocol setEventBuilder(EventBuilder event) {
        this.event = event;
        return this;
    }

    @Override
    public Response authenticated(AuthenticationSessionModel authSession, UserSessionModel userSession, ClientSessionContext clientSessionCtx) {
        return Response.status(302).location(URI.create(authSession.getRedirectUri())).build();
    }

    @Override
    public Response sendError(AuthenticationSessionModel authSession, Error error) {
        // never called
        return null;
    }

    @Override
    public void backchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        // do nothing
    }

    @Override
    public Response frontchannelLogout(UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {
        // never called
        return null;
    }

    @Override
    public Response finishLogout(UserSessionModel userSession) {
        // never called
        return null;
    }

    @Override
    public boolean requireReauthentication(UserSessionModel userSession, AuthenticationSessionModel authSession) {
        // never called
        return false;
    }

    @Override
    public void close() {

    }
}
