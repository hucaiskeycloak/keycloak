package org.keycloak.protocol.saml.mappers;

import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.models.ClientSessionContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.UserSessionModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class SAMLNameidSpprovidedidMapper extends AbstractSAMLProtocolMapper implements SAMLLoginResponseMapper {

    public static final String PROVIDER_ID = "saml-nameid-spprovidedid-mapper";

    private static final String NAME = "nameid.spprovidedid";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(NAME);
        property.setLabel("SAML NameID SPProvidedID");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Set a value to the SPProvidedID attribute of NameID element in SAML assertion.");
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return "SAML Assertion NameID mapper";
    }

    @Override
    public String getDisplayType() {
        return "SAML Assertion NameID SPProvidedID mapper";
    }

    @Override
    public String getHelpText() {
        return "Hardcode a value to SAML Assertion NameID SPProvidedID attribute.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public ResponseType transformLoginResponse(ResponseType response,
                                               ProtocolMapperModel mappingModel,
                                               KeycloakSession session,
                                               UserSessionModel userSession,
                                               ClientSessionContext clientSessionCtx) {
        String spProvidedId = mappingModel.getConfig().get(NAME);
        if (spProvidedId != null) {
            NameIDType nameID = (NameIDType) response.getAssertions().get(0)
                    .getAssertion().getSubject().getSubType().getBaseID();
            nameID.setSPProvidedID(spProvidedId);
        }
        return response;
    }
}
