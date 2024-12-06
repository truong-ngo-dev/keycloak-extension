package com.nob.keycloakextension;

import com.google.auto.service.AutoService;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

@AutoService(RealmResourceProviderFactory.class)
public class SmsOtpRestResourceProviderFactory implements RealmResourceProviderFactory {

    public static final String PROVIDER_ID = "sms-otp-2-factor-auth";

    @Override
    public RealmResourceProvider create(KeycloakSession keycloakSession) {
        return new SmsOtpRestResourceProvider(keycloakSession);
    }

    @Override
    public void init(Config.Scope scope) {

    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
