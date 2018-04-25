package br.gov.dataprev.keycloak.authenticator;

import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.forms.login.LoginFormsProviderFactory;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;

public class RecaptchaLoginFormsSpi  implements Spi {

    @Override
    public boolean isInternal() {
        return true;
    }

    @Override
    public String getName() {
        return "login";
    }

    @Override
    public Class<? extends Provider> getProviderClass() {
        return LoginFormsProvider.class;
    }

    @Override
    public Class<? extends ProviderFactory> getProviderFactoryClass() {
        return LoginFormsProviderFactory.class;
    }
}
