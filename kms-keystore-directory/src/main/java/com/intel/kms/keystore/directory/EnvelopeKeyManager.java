/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory;

import com.intel.mtwilson.util.crypto.keystore.PrivateKeyStore;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.kms.api.KeyAttributes;
import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author jbuhacoff
 */
public class EnvelopeKeyManager implements Closeable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(EnvelopeKeyManager.class);
    // constants
    public static final String ENVELOPE_KEYSTORE_FILE_PROPERTY = "envelope.keystore.file";
    public static final String ENVELOPE_KEYSTORE_PASSWORD_PROPERTY = "envelope.keystore.password";
    
    public static final String ENVELOPE_KEYSTORE_TYPE = "PKCS12"; // JKS and PKCS12 support storing private keys
    private PrivateKeyStore keystore;

    public EnvelopeKeyManager(File keystoreFile, char[] keystorePassword) throws KeyStoreException, IOException {
        this.keystore = new PrivateKeyStore(ENVELOPE_KEYSTORE_TYPE, keystoreFile, keystorePassword);
    }

    @Override
    public void close() throws IOException {
        keystore.close();
    }

    public boolean isEmpty() {
        try {
            return keystore.isEmpty();
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Keystore not open", e);
        }
    }

    /*
     //    @Override
     public void configure(Configuration configuration) {
     storageKeyAlgorithm = configuration.get("storage.key.algorithm", "AES");
     storageKeyLengthBits = Integer.valueOf(configuration.get("storage.key.length", "128"));
     }
     */
    /**
     * Precondition: keystore file exists (or throws FileNotFoundException)
     *
     * @return
     * @throws KeyStoreException
     * @throws FileNotFoundException
     * @throws IOException if keystore cannot be loaded
     * @throws NoSuchAlgorithmException is keystore cannot be loaded
     * @throws UnrecoverableKeyException if key cannot be loaded from keystore
     * @throws
     */
    
    /*
    public SecretKey loadStorageKey(String alias) throws KeyStoreException {
        if (!keystore.contains(alias)) {
            log.debug("Storage keystore does not contain alias: {}", alias);
            return null;
        }
        try {
            SecretKey key = keystore.get(alias);
            return key;
        } catch (GeneralSecurityException e) {
            throw new KeyStoreException("Cannot load key", e);
        }
    }
    * */

    /**
     *
     * @return default set of attributes for creating new storage keys
     */
    private KeyAttributes getDefaultKeyAttributes() {
        KeyAttributes keyAttributes = new KeyAttributes();
        keyAttributes.setAlgorithm("RSA");
        keyAttributes.setMode("ECB");
        keyAttributes.setDigestAlgorithm("SHA-256");
//        keyAttributes.id;
        keyAttributes.setKeyLength(2048);
//        keyAttributes.name;
        keyAttributes.setPaddingMode("OAEPWithSHA-256AndMGF1Padding");
        keyAttributes.setRole("keyEncryption");
//        keyAttributes.transferPolicy;  // no transfer policy because this key is not transferable;  maybe this should be a urn with "private" at the end.
        return keyAttributes;
    }

    public KeyAttributes createEnvelopeKey(PrivateKey privateKey, X509Certificate publicKeyCertificate) throws KeyStoreException {
        try {
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(getDefaultKeyAttributes());
            keyAttributes.setKeyId(new UUID().toString());

            // just in case the keystore already has an entry with this id:
            while (keystore.contains(keyAttributes.getKeyId())) {
                log.warn("Duplicate UUID detected: {}", keyAttributes.getKeyId());
                keyAttributes.setKeyId(new UUID().toString());
            }
            
            if( privateKey.getAlgorithm() != null && !privateKey.getAlgorithm().equalsIgnoreCase("RSA")) {
                log.warn("Unsupported private key algorithm {}", privateKey.getAlgorithm());
                keyAttributes.setAlgorithm(privateKey.getAlgorithm());
            }
            
            log.debug("Private key algorithm {} format {} encoded length: {}", privateKey.getAlgorithm(), privateKey.getFormat(), privateKey.getEncoded().length);

//            keyAttributes.setde = String.format("envelope-key:%s", keyAttributes.id);

            keystore.set(keyAttributes.getKeyId(), privateKey, new X509Certificate[] { publicKeyCertificate });

            return keyAttributes;

        } catch (GeneralSecurityException e) {
            throw new KeyStoreException("Cannot create storage key", e);
        }
    }

    public PrivateKeyStore getKeystore() {
        return keystore;
    }

    
}
