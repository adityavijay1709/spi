package com.github.eddykaya;

import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

public class CustomTermsAndConditionsFactory implements RequiredActionFactory {



    @Override
    public String getDisplayText() {
        return "Send email expiry"; // Display name of your custom required action
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return new CustomTermsAndConditions(session); // Return a new instance of your custom required action provider
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
        return "send_email_required_action";
    }
}
