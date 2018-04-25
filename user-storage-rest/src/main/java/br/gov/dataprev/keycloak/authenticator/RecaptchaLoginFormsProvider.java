package br.gov.dataprev.keycloak.authenticator;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.provider.Provider;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.net.URI;
import java.util.List;


public interface RecaptchaLoginFormsProvider extends Provider {

    String UPDATE_PROFILE_CONTEXT_ATTR = "updateProfileCtx";

    String IDENTITY_PROVIDER_BROKER_CONTEXT = "identityProviderBrokerCtx";

    String USERNAME_EDIT_DISABLED = "usernameEditDisabled";


    /**
     * Adds a script to the html header
     *
     * @param scriptUrl
     */
    void addScript(String scriptUrl);

    Response createResponse(UserModel.RequiredAction action);

    Response createForm(String form);

    Response createLogin();

    Response createPasswordReset();

    Response createLoginTotp();

    Response createRegistration();

    Response createInfoPage();

    Response createUpdateProfilePage();

    Response createIdpLinkConfirmLinkPage();

    Response createIdpLinkEmailPage();

    Response createLoginExpiredPage();

    Response createErrorPage(Response.Status status);

    Response createOAuthGrant();

    Response createCode();

    LoginFormsProvider setAuthenticationSession(AuthenticationSessionModel authenticationSession);

    LoginFormsProvider setClientSessionCode(String accessCode);

    LoginFormsProvider setAccessRequest(List<RoleModel> realmRolesRequested, MultivaluedMap<String,RoleModel> resourceRolesRequested, List<ProtocolMapperModel> protocolMappers);
    LoginFormsProvider setAccessRequest(String message);

    /**
     * Set one global error message.
     *
     * @param message key of message
     * @param parameters to be formatted into message
     */
    LoginFormsProvider setError(String message, Object ... parameters);

    /**
     * Set multiple error messages.
     *
     * @param messages to be set
     */
    LoginFormsProvider setErrors(List<FormMessage> messages);

    LoginFormsProvider addError(FormMessage errorMessage);

    /**
     * Add a success message to the form
     *
     * @param errorMessage
     * @return
     */
    LoginFormsProvider addSuccess(FormMessage errorMessage);

    LoginFormsProvider setSuccess(String message, Object ... parameters);

    LoginFormsProvider setInfo(String message, Object ... parameters);

    LoginFormsProvider setUser(UserModel user);

    LoginFormsProvider setResponseHeader(String headerName, String headerValue);

    LoginFormsProvider setFormData(MultivaluedMap<String, String> formData);

    LoginFormsProvider setAttribute(String name, Object value);

    LoginFormsProvider setStatus(Response.Status status);

    LoginFormsProvider setActionUri(URI requestUri);

    LoginFormsProvider setExecution(String execution);
}
