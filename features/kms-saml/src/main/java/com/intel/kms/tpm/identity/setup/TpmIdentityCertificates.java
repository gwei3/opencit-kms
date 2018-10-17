/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.tpm.identity.setup;

import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.setup.AbstractSetupTask;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.crypto.keystore.PublicKeyX509CertificateStore;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;

/**
 * @author jbuhacoff
 */
public class TpmIdentityCertificates extends AbstractSetupTask {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmIdentityCertificates.class);
    public static final String MTWILSON_TPM_IDENTITY_CERTIFICATES_FILE = "mtwilson.tpm.identity.certificates.file";
    public static final String MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD = "tpm_identity_certificates"; // the alias of the password
//    public static final String MTWILSON_API_URL = "mtwilson.api.url";
//    public static final String MTWILSON_API_USERNAME = "mtwilson.api.username";
//    public static final String MTWILSON_API_PASSWORD = "mtwilson.api.password";
//    public static final String MTWILSON_TLS_CERT_SHA256 = "mtwilson.tls.cert.sha256";
    private File tpmIdentityCertificatesFile;
    private Password keystorePassword;
//    private String mtwilsonApiUrl;
//    private String mtwilsonApiUsername;
//    private String mtwilsonApiPassword;
//    private String mtwilsonTlsCertSha256;

    public File getTpmIdentityCertificatesKeystoreFile() {
        return new File(getConfiguration().get(MTWILSON_TPM_IDENTITY_CERTIFICATES_FILE, Folders.configuration() + File.separator + "tpm.identity.jks"));
    }

    public Password getTpmIdentityCertificatesKeystorePassword() throws KeyStoreException, IOException {
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
            if (passwordVault.contains(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD)) {
                return passwordVault.get(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD);
            } else {
                return null;
            }
        }
    }

    @Override
    protected void configure() throws Exception {
        tpmIdentityCertificatesFile = getTpmIdentityCertificatesKeystoreFile();
//        mtwilsonApiUrl = getConfiguration().get(MTWILSON_API_URL);
//        mtwilsonApiUsername = getConfiguration().get(MTWILSON_API_USERNAME);
//        mtwilsonApiPassword = getConfiguration().get(MTWILSON_API_PASSWORD);
//        mtwilsonTlsCertSha256 = getConfiguration().get(MTWILSON_TLS_CERT_SHA256);
        if (tpmIdentityCertificatesFile.exists()) {
            log.debug("Configure TPM Identity certificates file at: {}", tpmIdentityCertificatesFile.getAbsolutePath());
            keystorePassword = getTpmIdentityCertificatesKeystorePassword();
            if (keystorePassword == null) {
                configuration("Trusted TPM Identity certificates file exists but password is missing");
            }
        }
        /*
         else {
         // if the tpmIdentity certs file doesn't exist, we should have api url and tls cert sha256 to download it
            
         if (mtwilsonApiUrl == null) {
         configuration("Missing Mt Wilson API URL");
         }
         if (mtwilsonApiUsername == null) {
         configuration("Missing Mt Wilson API username");
         }
         if (mtwilsonApiPassword == null) {
         configuration("Missing Mt Wilson API password");
         }
         if (mtwilsonTlsCertSha256 == null) {
         configuration("Missing Mt Wilson TLS certificate SHA-256 fingerprint");
         }
         }
         */
    }

    @Override
    protected void validate() throws Exception {

        if (tpmIdentityCertificatesFile.exists()) {
            log.debug("Validate TPM Identity certificates file at: {}", tpmIdentityCertificatesFile.getAbsolutePath());
            // make sure we have a password for the cert keystore
            if (keystorePassword == null) {
                validation("Missing password for TPM Identity certificate authorities file");
            } else {
                // make sure there's at least one trusted certificate in it
                try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore("JKS", new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
                    if (store.isEmpty()) {
                        //validation("No trusted TPM Identity certificate authorities");  // allow it to be empty, user will add cert later
                        log.debug("TPM Identity certificate authorities list is empty");
                    }
                }
            }
        } else {
            validation("Trusted TPM Identity certificate authorities file is missing");
        }
    }

    @Override
    protected void execute() throws Exception {
        if (keystorePassword == null || keystorePassword.toCharArray().length == 0) {
            // generate a keystore password
            keystorePassword = new Password(RandomUtil.randomBase64String(16).toCharArray());

            try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(getConfiguration())) {
                passwordVault.set(MTWILSON_TPM_IDENTITY_CERTIFICATES_PASSWORD, keystorePassword);
            }

        }

        /*
         // download trusted tpmIdentity certificate authorities from mtwilson
         Properties mtwilsonProperties = new Properties();
         mtwilsonProperties.setProperty("mtwilson.api.url", mtwilsonApiUrl);
         mtwilsonProperties.setProperty("mtwilson.api.username", mtwilsonApiUsername);
         mtwilsonProperties.setProperty("mtwilson.api.password", mtwilsonApiPassword);
         mtwilsonProperties.setProperty("mtwilson.api.tls.policy.certificate.sha256", mtwilsonTlsCertSha256); // for other options see PropertiesTlsPolicyFactory in mtwilson-util-jaxrs2-client
         MtWilsonClient mtwilson = new MtWilsonClient(mtwilsonProperties);
         X509Certificate certificate = mtwilson.getTargetPath("ca-certificates/tpmIdentity").request(CryptoMediaType.APPLICATION_PKIX_CERT).get(X509Certificate.class);
        
         */
        // store the certificate
        try (PublicKeyX509CertificateStore store = new PublicKeyX509CertificateStore("JKS", new FileResource(tpmIdentityCertificatesFile), keystorePassword.toCharArray())) {
//            store.set(Sha256Digest.digestOf(certificate.getEncoded()).toHexString(), certificate);
            store.modified(); // will cause the keystore to save even though it's empty
        }

    }
}
