package br.gov.dataprev.keycloak.authentication;

import java.util.Map;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.jboss.logging.Logger;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.storage.UserStorageManager;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.UserStorageProviderFactory;
import org.keycloak.storage.UserStorageProviderModel;

import br.gov.dataprev.keycloak.exceptions.CPFInexistenteException;
import br.gov.dataprev.keycloak.exceptions.ServicoIndisponivelException;
import br.gov.dataprev.keycloak.storage.cidadao.CidadaoIdentityStore;
import br.gov.dataprev.keycloak.storage.cidadao.CidadaoStorageProvider;
import br.gov.dataprev.keycloak.storage.cidadao.model.Cidadao;
import br.gov.dataprev.keycloak.storage.rest.RESTConfig;

public class DataprevAuthenticator extends AbstractUsernameFormAuthenticator implements Authenticator {
	
	Logger logger = Logger.getLogger(this.getClass());
	CidadaoIdentityStore identityStore;
	public static final String NUM_TENTATIVAS = "NUM_TENTATIVAS";
    public static final String RECAPTCHA_KEY = "RECAPTCHA_KEY";
    public static final String RECAPTCHA_SECRET = "RECAPTCHA_SECRET";

	@Override
	public void close() {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		logger.info("Authenticate");
		if (context.getAuthenticatorConfig() != null) {
			Map<String, String> config = context.getAuthenticatorConfig().getConfig();
			
			if (config.containsKey(NUM_TENTATIVAS)) {
				Integer tentativas = Integer.valueOf(config.get("IP_INICIO"));
				logger.info("Tentativas: " + tentativas);
				Response challengeResponse = challenge(context, null);
				context.challenge(challengeResponse);
				return;
			}			
		}
		
		// Caso cancele a challenge
        MultivaluedMap<String, String> inputData = context.getHttpRequest().getDecodedFormParameters();
        if (inputData.containsKey("cancel")) {
            context.resetFlow();
            return;
        }
		
		MultivaluedMap<String, String> formData = new MultivaluedMapImpl<>();
        String loginHint = context.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM);

        String rememberMeUsername = AuthenticationManager.getRememberMeUsername(context.getRealm(), context.getHttpRequest().getHttpHeaders());

        if (loginHint != null || rememberMeUsername != null) {
            if (loginHint != null) {
                formData.add(AuthenticationManager.FORM_USERNAME, loginHint);
            } else {
                formData.add(AuthenticationManager.FORM_USERNAME, rememberMeUsername);
                formData.add("rememberMe", "on");
            }
        }
        Response challengeResponse = challenge(context, formData);
        context.challenge(challengeResponse);
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		logger.info("Ação do Processo de Autenticação Dataprev");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }
        if (!validateForm(context, formData)) {
            return;
        }
        context.success();
	}
	
	protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
        return validaUsuario(context, formData);
    }
	
	protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {
		logger.info("Challenge");
        LoginFormsProvider forms = context.form();
        if (formData.size() > 0) forms.setFormData(formData);
        return forms.createLogin();
    }


	@Override
	public boolean requiresUser() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		// TODO Auto-generated method stub
		
	}
	
	public boolean validaUsuario(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = inputData.getFirst(AuthenticationManager.FORM_USERNAME);
        if (username == null) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            Response challengeResponse = invalidUser(context);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse);
            return false;
        }

        // remove leading and trailing whitespace
        username = username.trim();

        context.getEvent().detail(Details.USERNAME, username);
        context.getAuthenticationSession().setAuthNote(AbstractUsernameFormAuthenticator.ATTEMPTED_USERNAME, username);

        
        // Customização do login
        UserModel user = null;
        try {
           
        	user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
            
        	
            
/*            for (UserStorageProviderModel model : context.getRealm().getUserStorageProviders()) {
            	if (model.getProviderId().equals("CidadaoStorageProvider")) {
                UserStorageProviderFactory factory = (UserStorageProviderFactory) context.getSession().getKeycloakSessionFactory().getProviderFactory(UserStorageProvider.class, model.getProviderId());
                CidadaoStorageProvider provider = (CidadaoStorageProvider) factory.create(context.getSession());
                user = provider.getUserById(username, context.getRealm());
            	}
            }*/
            
            
        	//RESTConfig config = new RESTConfig();
        	//Cidadao cidadao = searchById(Long.valueOf(username), config);
        	//user = new UserAdapter(context.getSession(), context.getRealm(),  , identityStore, cidadao);

       
            
        } catch (NumberFormatException e) {
			logger.info("##### CPFInvalidoException");
            context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);
            Response challengeResponse = invalidUser(context);
            context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, challengeResponse);
            return false;
		} /*catch (ServicoIndisponivelException e) {
			logger.info("##### ServicoIndisponivelException");
            //context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);
            Response challengeResponse = context.form().setError("cidadaoBRIndisponivel").createLogin();
            context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR, challengeResponse);
			return false;
		} catch (CPFInexistenteException e) {
			logger.info("##### CPFInvalidoException");
            context.getEvent().error(Errors.IDENTITY_PROVIDER_ERROR);
            Response challengeResponse = context.form().setError("cpfInvalido").createLogin();
            context.failureChallenge(AuthenticationFlowError.UNKNOWN_USER, challengeResponse);
            return false;
		}
        */
        

        if (invalidUser(context, user)) {
            return false;
        }

        if (!validatePassword(context, user, inputData)) {
            return false;
        }

        if (!enabledUser(context, user)) {
            return false;
        }

        String rememberMe = inputData.getFirst("rememberMe");
        boolean remember = rememberMe != null && rememberMe.equalsIgnoreCase("on");
        if (remember) {
            context.getAuthenticationSession().setAuthNote(Details.REMEMBER_ME, "true");
            context.getEvent().detail(Details.REMEMBER_ME, "true");
        } else {
            context.getAuthenticationSession().removeAuthNote(Details.REMEMBER_ME);
        }
        context.setUser(user);
        return true;
    }
	
	private Cidadao searchById(Long cpf, RESTConfig config) throws ServicoIndisponivelException, CPFInexistenteException {
		
		Client client = ClientBuilder.newClient();
		WebTarget api = client.target(UriBuilder.fromPath(config.getConnectionUrl()));
		Cidadao cidadao = null;
		Response response = null;
		try {
			response = api.path("cidadaos/{cpf}")
					.resolveTemplate("cpf", cpf.toString())
					.request(MediaType.APPLICATION_JSON)
					.get();
			
			if (response == null) {
				throw new RuntimeException("Ocorre um problema ao processar a requisição");
			}
			
			if (response.getStatus() == 404) {
				throw new CPFInexistenteException("Não foi possível consultar pelo CPF");
			}
			
			if (response.getStatus() == 200) {
				cidadao = response.readEntity(Cidadao.class);
			}
			
		} catch (javax.ws.rs.ProcessingException c) {
			throw new ServicoIndisponivelException("serviceUnavailable");
			
		} finally {
			if (response != null) response.close();
		}
		
		return cidadao;
	}
	

}
