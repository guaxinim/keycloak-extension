package br.gov.dataprev.keycloak.authenticator;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import java.util.ArrayList;
import java.util.List;

public class RecaptchaAuthenticatorFormFactory implements AuthenticatorFactory {

    Logger logger = Logger.getLogger(this.getClass());
    public static final String PROVIDER_ID = "auth-recaptcha-form";
    public static final RecaptchaAuthenticatorForm SINGLETON = new RecaptchaAuthenticatorForm();

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("SITE_KEY");
        property.setLabel("Recaptcha Site Key");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Definição da chave (site key) do Recaptcha do Google");
        configProperties.add(property);

        ProviderConfigProperty property2;
        property2 = new ProviderConfigProperty();
        property2.setName("SITE_SECRET");
        property2.setLabel("Recaptcha Site Secret");
        property2.setType(ProviderConfigProperty.STRING_TYPE);
        property2.setHelpText("Definição da secret (site secret) do Recaptcha do Google");
        configProperties.add(property2);

        ProviderConfigProperty property3;
        property3 = new ProviderConfigProperty();
        property3.setName("QUANTIDADE_ERROS_LOGIN");
        property3.setLabel("Quatidade de erros");
        property3.setType(ProviderConfigProperty.STRING_TYPE);
        property3.setHelpText("Quantidade de erros de login para ativação do Recaptcha");
        configProperties.add(property3);
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        logger.debug("Criando Authenticator Username Password Form with Recaptcha");
        return SINGLETON;
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

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getReferenceCategory() {
        return UserCredentialModel.PASSWORD;
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public String getDisplayType() {
        return "Username Password Form with Recaptcha on many authentication errors";
    }

    @Override
    public String getHelpText() {
        return "Validates a username and password and also a Recaptcha from login form.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

}
