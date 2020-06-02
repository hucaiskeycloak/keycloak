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

public class SAMLNameIDValueMapper extends AbstractSAMLProtocolMapper implements SAMLLoginResponseMapper {

    public static final String PROVIDER_ID = "saml-nameid-value-mapper";

    private static final String NAME = "my.nameid.attribute";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();

    static {
        ProviderConfigProperty property = new ProviderConfigProperty();
        property.setName(NAME);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setLabel("User Attribute");
        property.setHelpText("The value of NameID will be set to the value of the specified user attribute.");
        configProperties.add(property);
    }

    @Override
    public String getDisplayCategory() {
        return "SAML NameID mapper";
    }

    @Override
    public String getDisplayType() {
        return "NameID Value mapper";
    }

    @Override
    public ResponseType transformLoginResponse(ResponseType response,
                                               ProtocolMapperModel mappingModel,
                                               KeycloakSession session,
                                               UserSessionModel userSession,
                                               ClientSessionContext clientSessionCtx) {
        String key = mappingModel.getConfig().get(NAME);
        List<String> values = userSession.getUser().getAttribute(key);
        if (values != null && !values.isEmpty()) {
            String value = values.get(0);
            NameIDType nameID = (NameIDType) response.getAssertions().get(0).getAssertion()
                    .getSubject().getSubType().getBaseID();
            nameID.setValue(value);
        }
        return response;
    }

    @Override
    public String getHelpText() {
        return "Map the value of a custom user attribute to the value of NameID element in SAML Assertion.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
