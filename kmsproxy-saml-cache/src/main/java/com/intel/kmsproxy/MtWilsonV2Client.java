/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.mtwilson.as.rest.v2.model.HostAttestation;
import com.intel.mtwilson.attestation.client.jaxrs.HostAttestations;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import java.io.IOException;
import java.security.KeyStoreException;
import java.util.Properties;

/**
 *
 * @author jbuhacoff
 */
public class MtWilsonV2Client implements SecurityAssertionProvider {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(MtWilsonV2Client.class);
    
    @Override
    public String getAssertionForSubject(String subject) throws IOException {
        HostAttestations client = getMtWilsonClient();
        HostAttestation query = new HostAttestation();
        query.setAikPublicKeySha1(subject);
        String saml = client.createHostAttestationSaml(query);
        return saml;
    }
    
    private HostAttestations getMtWilsonClient() throws IOException {
        Configuration configuration = ConfigurationFactory.getConfiguration();
        MtWilsonClientConfiguration clientConfig = new MtWilsonClientConfiguration(configuration);
        Properties properties = new Properties();
        try {
        String password = new String(clientConfig.getKeystorePassword().toCharArray());
        properties.setProperty("mtwilson.api.url", String.format("%s/v2", clientConfig.getEndpointURL().toExternalForm()));
        properties.setProperty("mtwilson.api.keystore", clientConfig.getKeystorePath());
        properties.setProperty("mtwilson.api.keystore.password", password);
        properties.setProperty("mtwilson.api.key.alias", clientConfig.getEndpointUsername());
        properties.setProperty("mtwilson.api.key.password", password);
        properties.setProperty("mtwilson.api.tls.policy.certificate.sha1", configuration.get(MtWilsonClientConfiguration.MTWILSON_TLS_CERT_SHA1));
        }
        catch(KeyStoreException e) {
            log.error("Cannot load password", e);
            throw new IOException(e);
        }
        try {
        HostAttestations client = new HostAttestations(properties);
        return client;
        }
        catch(Exception e) {
            log.error("Cannot instantiate Mt Wilson v2 client", e);
            throw new IOException(e);
        }
    }
}
