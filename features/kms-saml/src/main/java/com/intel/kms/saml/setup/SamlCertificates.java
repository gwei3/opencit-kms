/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.saml.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;
import java.io.File;

/**
 * @author jbuhacoff
 */
public class SamlCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SamlCertificates.class);
    public static final String MTWILSON_SAML_CERTIFICATES_FILE = "mtwilson.saml.certificates.file";
    public static final String MTWILSON_SAML_CERTIFICATES_PASSWORD = "saml_certificates"; // the alias of the password
//    public static final String MTWILSON_API_URL = "mtwilson.api.url";
//    public static final String MTWILSON_API_USERNAME = "mtwilson.api.username";
//    public static final String MTWILSON_API_PASSWORD = "mtwilson.api.password";
//    public static final String MTWILSON_TLS_CERT_SHA1 = "mtwilson.tls.cert.sha1";
    private File samlCertificatesFile;
    private Password keystorePassword;
//    private String mtwilsonApiUrl;
//    private String mtwilsonApiUsername;
//    private String mtwilsonApiPassword;
//    private String mtwilsonTlsCertSha1;

    @Override
    protected void configure() throws Exception {
        samlCertificatesFile = new File(getConfiguration().get(MTWILSON_SAML_CERTIFICATES_FILE, Folders.configuration() + File.separator + "saml.jks"));
//        mtwilsonApiUrl = getConfiguration().get(MTWILSON_API_URL);
//        mtwilsonApiUsername = getConfiguration().get(MTWILSON_API_USERNAME);
//        mtwilsonApiPassword = getConfiguration().get(MTWILSON_API_PASSWORD);
//        mtwilsonTlsCertSha1 = getConfiguration().get(MTWILSON_TLS_CERT_SHA1);
        if (samlCertificatesFile.exists()) {
            log.debug("Configure SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {

                if (passwordVault.contains(MTWILSON_SAML_CERTIFICATES_PASSWORD)) {
                    keystorePassword = passwordVault.get(MTWILSON_SAML_CERTIFICATES_PASSWORD);
                } else {
                    configuration("Trusted SAML certificates file exists but password is missing");
                }
            }
        }
        /*
         else {
         // if the saml certs file doesn't exist, we should have api url and tls cert sha1 to download it
            
         if (mtwilsonApiUrl == null) {
         configuration("Missing Mt Wilson API URL");
         }
         if (mtwilsonApiUsername == null) {
         configuration("Missing Mt Wilson API username");
         }
         if (mtwilsonApiPassword == null) {
         configuration("Missing Mt Wilson API password");
         }
         if (mtwilsonTlsCertSha1 == null) {
         configuration("Missing Mt Wilson TLS certificate SHA-1 fingerprint");
         }
         }
         */
    }

    @Override
    protected void validate() throws Exception {

        if (samlCertificatesFile.exists()) {
            log.debug("Validate SAML certificates file at: {}", samlCertificatesFile.getAbsolutePath());
            // make sure we have a password for the cert keystore
            if (keystorePassword == null) {
                validation("Missing password for SAML certificate authorities file");
            } else {
                // make sure there's at least one trusted certificate in it

                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore("JKS", new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
//                validation("No trusted SAML certificate authorities");// allow it to be empty, user will add cert later
                        log.debug("SAML certificate authorities list is empty");
                    }
                }
            }
        } else {
            validation("Trusted SAML certificate authorities file is missing");
        }
    }

    @Override
    protected void execute() throws Exception {
        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            // generate a keystore password
            keystorePassword = new Password(RandomUtil.randomBase64String(16).toCharArray());

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
                passwordVault.set(MTWILSON_SAML_CERTIFICATES_PASSWORD, keystorePassword);
            }

        }

        /*
         // download trusted saml certificate authorities from mtwilson
         Properties mtwilsonProperties = new Properties();
         mtwilsonProperties.setProperty("mtwilson.api.url", mtwilsonApiUrl);
         mtwilsonProperties.setProperty("mtwilson.api.username", mtwilsonApiUsername);
         mtwilsonProperties.setProperty("mtwilson.api.password", mtwilsonApiPassword);
         mtwilsonProperties.setProperty("mtwilson.api.tls.policy.certificate.sha1", mtwilsonTlsCertSha1); // for other options see PropertiesTlsPolicyFactory in mtwilson-util-jaxrs2-client
         MtWilsonClient mtwilson = new MtWilsonClient(mtwilsonProperties);
         X509Certificate certificate = mtwilson.getTargetPath("ca-certificates/saml").request(CryptoMediaType.APPLICATION_PKIX_CERT).get(X509Certificate.class);
         */

        // store the certificate
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore("JKS", new FileResource(samlCertificatesFile), keystorePassword.toCharArray())) {
            //store.set(Sha256Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
