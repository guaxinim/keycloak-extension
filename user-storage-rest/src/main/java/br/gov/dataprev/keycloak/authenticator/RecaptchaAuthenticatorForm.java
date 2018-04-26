package br.gov.dataprev.keycloak.authenticator;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.resteasy.specimpl.MultivaluedMapImpl;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.AbstractUsernameFormAuthenticator;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class RecaptchaAuthenticatorForm extends AbstractUsernameFormAuthenticator implements Authenticator {

    protected static ServicesLogger log = ServicesLogger.LOGGER;
    private boolean recaptchaOn = false;

    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String SITE_KEY = "SITE_KEY";
    public static final String SITE_SECRET = "SITE_SECRET";
    public static final String QUANTIDADE_ERROS_LOGIN = "QUANTIDADE_ERROS_LOGIN";

    @Override
    public void action(AuthenticationFlowContext context) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        if (formData.containsKey("cancel")) {
            context.cancelLogin();
            return;
        }

        // Quando ativo o recaptcha, executa a validação antes mesmo de validar o usuário
        recaptchaOn = (getParametro(context,"recaptcha") != null);
        if (recaptchaOn) {
            boolean ok = validateFormWithRecaptcha(context, context.form());
            if (!ok) {
                // Retorna mensagem de erro especifica do recaptcha
                context.form().addError(new FormMessage(null, Messages.RECAPTCHA_FAILED));
                Response challengeResponse = context.form().createErrorPage(Response.Status.NOT_ACCEPTABLE);
                context.challenge(challengeResponse);
                return;
            }
        }
        if (!validateForm(context, formData)) {
            // A cada erro verifica se ha necessidade do recaptcha
            verificaNecessidadeRecaptcha(context, context.form());
            Response challengeResponse = context.form().createLogin();
            context.challenge(challengeResponse);
            return;
        }
        context.success();
        context.getSession().removeAttribute("tentativas");
    }

    protected boolean validateForm(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {

        boolean valid = validateUserAndPassword(context, formData);
        // Aumenta a quantidade de tentativas de login a cada erro
        if (!valid) {

            log.info("VALOR: " + getParametro(context, "tentativas"));

            Integer tentativas = 0;
            if (isInteger(getParametro(context, "tentativas"), 10))
                tentativas = Integer.valueOf(getParametro(context, "tentativas"));
            setParametro(context, "tentativas", String.valueOf(++tentativas));

        }

        return valid;
    }

    private String getParametro(AuthenticationFlowContext context, String chave) {
        return (String) context.getAuthenticationSession().getUserSessionNotes().get(chave);
    }

    private void setParametro(AuthenticationFlowContext context, String chave, String valor) {
        context.getAuthenticationSession().setUserSessionNote(chave, valor);
    }


    @Override
    public void authenticate(AuthenticationFlowContext context) {
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
    public boolean requiresUser() {
        return false;
    }

    protected Response challenge(AuthenticationFlowContext context, MultivaluedMap<String, String> formData) {

        LoginFormsProvider form = context.form();
        if (formData.size() > 0) form.setFormData(formData);

        // Verifica necessidade do login mesmo na primeira exibição da pagina para casos que o usuario mandou um GET direto
        verificaNecessidadeRecaptcha(context, form);

        return form.createLogin();
    }

    private void verificaNecessidadeRecaptcha(AuthenticationFlowContext context, LoginFormsProvider form) {
        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        recaptchaOn = false;

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null
                ) {
            // Recaptcha não configurado
            form.setAttribute("recaptchaRequired", false);
        } else {
            Integer quantidade_erros = 9999;
            if (isInteger(captchaConfig.getConfig().get(QUANTIDADE_ERROS_LOGIN), 10)) {
                quantidade_erros = Integer.valueOf(captchaConfig.getConfig().get(QUANTIDADE_ERROS_LOGIN));
            }

            Integer tentativas = 0;
            if (isInteger(getParametro(context, "tentativas"), 10)) {
                tentativas = Integer.valueOf(getParametro(context, "tentativas"));
            }

            log.info("TENTATIVAS: " + tentativas);
            log.info("MAXIMO: " + quantidade_erros);

            // Exibe o recaptcha caso exceda a quantidade de tentativas
            if (quantidade_erros != null && tentativas >= quantidade_erros) {
                form.setAttribute("recaptchaRequired", true);
                form.setAttribute("recaptchaSiteKey", captchaConfig.getConfig().get(SITE_KEY));
                form.addScript("https://www.google.com/recaptcha/api.js");
                setParametro(context, "recaptcha", "true");
            }
        }
    }

    public static boolean isInteger(String s, int radix) {
        if(s == null || s.isEmpty()) return false;
        for(int i = 0; i < s.length(); i++) {
            if(i == 0 && s.charAt(i) == '-') {
                if(s.length() == 1) return false;
                else continue;
            }
            if(Character.digit(s.charAt(i),radix) < 0) return false;
        }
        return true;
    }

    public boolean validateFormWithRecaptcha(AuthenticationFlowContext context, LoginFormsProvider form) {
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        List<FormMessage> errors = new ArrayList<>();
        boolean success = false;
        context.getEvent().detail(Details.REGISTER_METHOD, "form");

        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String secret = captchaConfig.getConfig().get(SITE_SECRET);

            success = validateRecaptcha(context, success, captcha, secret);
        }
        if (success) {
            return true;
        } else {
            errors.add(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            formData.remove(G_RECAPTCHA_RESPONSE);
            return false;
        }
    }

    protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
        List<NameValuePair> formparams = new LinkedList<>();
        formparams.add(new BasicNameValuePair("secret", secret));
        formparams.add(new BasicNameValuePair("response", captcha));
        formparams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formparams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                Object val = json.get("success");
                success = Boolean.TRUE.equals(val);
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }


    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        // never called
    }

    @Override
    public void close() {

    }
}
