package br.gov.dataprev.keycloak.authentication;

import java.util.ArrayList;
import java.util.List;

import org.jboss.logging.Logger;
import org.keycloak.Config.Scope;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class DataprevAuthenticatorFactory implements AuthenticatorFactory {
	
	Logger logger = Logger.getLogger(this.getClass());

    public static final String PROVIDER_ID = "dataprev-authenticator";
    private static final DataprevAuthenticator SINGLETON = new DataprevAuthenticator();

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    public static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED
    };

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName("NUM_TENTATIVAS");
        property.setLabel("Tentativas de login");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText("Número de tentativas de login para ativação do Recaptcha");
        configProperties.add(property);

        ProviderConfigProperty property2;
        property2 = new ProviderConfigProperty();
        property2.setName("RECAPTCHA_KEY");
        property2.setLabel("Recaptcha site key");
        property2.setType(ProviderConfigProperty.STRING_TYPE);
        property2.setHelpText("Chave do Recaptcha gerada no Google");
        configProperties.add(property2);
        
        ProviderConfigProperty property3;
        property3 = new ProviderConfigProperty();
        property3.setName("RECAPTCHA_SECRET");
        property3.setLabel("Recaptcha secret");
        property3.setType(ProviderConfigProperty.STRING_TYPE);
        property3.setHelpText("Secret do Recaptcha gerada no Google");
        configProperties.add(property3);
    }

    public boolean isUserSetupAllowed() {
        return true;
    }

    public void close() {

    }

    public String getId() {
        return PROVIDER_ID;
    }

    public String getDisplayType() {
        return "Autenticação Adaptativa Dataprev";
    }

    public String getReferenceCategory() {
        return "Autenticação Adaptativa";
    }

    public boolean isConfigurable() {
        return true;
    }

    public String getHelpText() {
        return "Autenticação adaptativa customizada conforme regras da Dataprev";
    }
    
	@Override
	public Authenticator create(KeycloakSession arg0) {
		logger.debug("Criando Authenticator Dataprev");
        return SINGLETON;
	}

	@Override
	public void init(Scope arg0) {
		logger.info("Registrando Factory da Autenticação Dataprev");
		
	}

	@Override
	public void postInit(KeycloakSessionFactory arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		 return configProperties;
	}

}
