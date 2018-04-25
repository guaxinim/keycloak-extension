package br.gov.dataprev.keycloak.authenticator;

public enum RecaptchaLoginFormsPages {

    LOGIN, LOGIN_TOTP, LOGIN_CONFIG_TOTP, LOGIN_VERIFY_EMAIL,
    LOGIN_IDP_LINK_CONFIRM, LOGIN_IDP_LINK_EMAIL,
    OAUTH_GRANT, LOGIN_RESET_PASSWORD, LOGIN_UPDATE_PASSWORD, REGISTER, INFO, ERROR, LOGIN_UPDATE_PROFILE, LOGIN_PAGE_EXPIRED, CODE;
}
