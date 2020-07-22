package org.keycloak.protocol.onepass;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.AuthorizationEndpointBase;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.CommonClientSessionModel;

import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class OnePassService extends AuthorizationEndpointBase {

    private ClientModel client;
    private String clientId;
    private String token;
    private String redirectURL;

    public OnePassService(RealmModel realm, EventBuilder event) {
        super(realm, event);
    }

    @GET
    @NoCache
    public Response handleGET(@QueryParam("client_id") String clientId,
                              @QueryParam("token") String token,
                              @QueryParam("redirect_url") String redirectURL) {
        this.clientId = clientId;
        this.token = token;
        this.redirectURL = redirectURL;
        return handle();
    }

    @POST
    @NoCache
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response handlePOST(@FormParam("client_id") String clientId,
                               @FormParam("token") String token,
                               @FormParam("redirect_url") String redirectURL) {
        this.clientId = clientId;
        this.token = token;
        this.redirectURL = redirectURL;
        return handle();
    }

    private Response handle() {
        Response basicRealmError = realmBasicCheck();
        if (basicRealmError != null) {
            return basicRealmError;
        }
        Response basicParametersError = parametersBasicCheck();
        if (basicParametersError != null) {
            return basicParametersError;
        }
        Response basicClientError = clientBasicCheck();
        if (basicClientError != null) {
            return basicClientError;
        }
        return handleRequest();
    }

    private Response realmBasicCheck() {
        if (!checkSSL()) {
            event.event(EventType.LOGIN);
            event.error(Errors.SSL_REQUIRED);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.HTTPS_REQUIRED);
        }
        if (!realm.isEnabled()) {
            event.event(EventType.LOGIN_ERROR);
            event.error(Errors.REALM_DISABLED);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.REALM_NOT_ENABLED);
        }
        return null;
    }

    private boolean checkSSL() {
        if (session.getContext().getUri().getBaseUri().getScheme().equals("https")) {
            return true;
        } else {
            return !realm.getSslRequired().isRequired(clientConnection);
        }
    }

    private Response parametersBasicCheck() {
        if (clientId == null || token == null) {
            event.event(EventType.LOGIN);
            event.error("client_id and/or token missing");
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUEST);
        }
        return null;
    }

    private Response clientBasicCheck() {
        client = realm.getClientByClientId(clientId);
        if (client == null) {
            event.event(EventType.CLIENT_LOGIN);
            event.error(Errors.CLIENT_NOT_FOUND);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.UNKNOWN_LOGIN_REQUESTER);
        }
        if (!client.isEnabled()) {
            event.event(EventType.CLIENT_LOGIN);
            event.error(Errors.CLIENT_DISABLED);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.LOGIN_REQUESTER_NOT_ENABLED);
        }
        if (!client.getProtocol().equals(OnePassProtocol.PROTOCOL_NAME)) {
            event.event(EventType.CLIENT_LOGIN);
            event.error(Errors.INVALID_CLIENT);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REQUESTER);
        }
        if (redirectURL == null || redirectURL.isEmpty()) {
            redirectURL = client.getBaseUrl();
        }
        if (redirectURL == null || redirectURL.isEmpty() || !(redirectURL.startsWith("http://") || redirectURL.startsWith("https://"))) {
            event.event(EventType.CLIENT_LOGIN);
            event.error(Errors.INVALID_REDIRECT_URI);
            return ErrorPage.error(session, null, Response.Status.BAD_REQUEST, Messages.INVALID_REDIRECT_URI);
        }
        return null;
    }

    private Response handleRequest() {
        event.event(EventType.LOGIN);

        AuthenticationSessionModel authSession = createAuthenticationSession(client, null);
        authSession.setProtocol(OnePassProtocol.PROTOCOL_NAME);
        authSession.setRedirectUri(redirectURL);
        authSession.setAction(CommonClientSessionModel.Action.AUTHENTICATE.name());
        authSession.setClientNote(OnePassProtocol.PROTOCOL_TOKEN_NAME, token);

        return handleBrowserAuthenticationRequest(authSession, null, false, false);
    }

}
