/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.configuration.ReadonlyConfiguration;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;

/**
 * To use password-based HTTP BASIC authorization with the user server, the
 * client must be initialized with the following properties: endpoint.url,
 * login.basic.username, login.basic.password, and any valid TLS policy. The
 * example below uses the Properties format, a sample URL, and a sample TLS
 * certificate SHA-1 fingerprint:
 *
 * <pre>
 * endpoint.url=https://kms.example.com
 * tls.policy.certificate.sha256=751c70c9f2789d3c17f29478eacc158e68436ec6d7808b1f76fb80fe43a45b90
 * login.basic.username=client-username
 * login.basic.password=client-password
 * </pre>
 *
 * @author jbuhacoff
 */
public class Login extends JaxrsClient {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Login.class);
    private ReadonlyConfiguration configuration;
    
    public Login(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
        this.configuration = new ReadonlyConfiguration(new PropertiesConfiguration(properties));
    }

    public Login(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
        this.configuration = new ReadonlyConfiguration(configuration);
    }

    public static class LoginRequest {

        public String username;
        public String password;

        public LoginRequest(String username, String password) {
            this.username = username;
            this.password = password;
        }
    }

    public static class LoginResponse {

        private String authorizationToken;

        public String getAuthorizationToken() {
            return authorizationToken;
        }

        public void setAuthorizationToken(String authorizationToken) {
            this.authorizationToken = authorizationToken;
        }
    }

    public String getAuthorizationToken() {
        LoginRequest loginRequest = new LoginRequest(configuration.get("login.basic.username"), configuration.get("login.basic.password"));
        return getAuthorizationToken(loginRequest);
    }
    public String getAuthorizationToken(LoginRequest loginRequest) {
        log.debug("getAuthorizationToken: {}", getTarget().getUri().toString());
        LoginResponse loginResponse = getTarget().path("/v1/login").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(loginRequest), LoginResponse.class);
        return loginResponse.getAuthorizationToken();
    }

    public void logout(String token) {
        LoginResponse logoutRequest = new LoginResponse();
        logoutRequest.setAuthorizationToken(token);
        getTarget().path("/v1/logout").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(logoutRequest));
    }
}
