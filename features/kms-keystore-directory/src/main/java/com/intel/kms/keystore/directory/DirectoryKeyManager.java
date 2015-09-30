/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.keystore.directory;

import com.intel.kms.api.KeyDescriptor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configurable;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaCredentialX509;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
import com.intel.dcsg.cpg.crypto.file.KeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.PemKeyEncryption;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeFactory;
import com.intel.dcsg.cpg.crypto.file.RsaPublicKeyProtectedPemKeyEnvelopeOpener;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.dcsg.cpg.io.ByteArray;
import com.intel.dcsg.cpg.io.UUID;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.mtwilson.Folders;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyLogMarkers;
import com.intel.kms.api.KeyTransferPolicy;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.fault.InvalidParameter;
import com.intel.kms.api.fault.MissingRequiredParameter;
import com.intel.kms.api.fault.UnsupportedAlgorithm;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.fault.KeyNotFound;
import com.intel.kms.api.fault.KeyTransferProtectionNotAcceptable;
import com.intel.kms.keystore.directory.setup.EnvelopeKey;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.core.PasswordVaultFactory;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.Protection;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import com.intel.mtwilson.util.tpm12.DataBind;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.lang3.ArrayUtils;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.kms.user.jaxrs.UserRepository;
import com.intel.mtwilson.setup.faults.ConfigurationFault;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import org.apache.commons.lang3.StringUtils;

/**
 *
 * @author jbuhacoff
 */
public class DirectoryKeyManager implements KeyManager, Configurable {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DirectoryKeyManager.class);
    private Configuration configuration;
    private File keysDirectory;
    private ObjectMapper mapper;
    private JacksonFileRepository<CipherKey, String> repository;

    public DirectoryKeyManager() throws IOException {
        keysDirectory = new File(Folders.repository("keys"));
        if (!keysDirectory.exists()) {
            if (!keysDirectory.mkdirs()) {
                log.error("Cannot create keys directory");
            }
        }
        configuration = ConfigurationFactory.getConfiguration();
        mapper = JacksonObjectMapperProvider.createDefaultMapper();
        repository = new JacksonFileRepository<>(keysDirectory);
    }

    public EnvelopeKeyManager getEnvelopeKeyManager() throws KeyStoreException, IOException {
        String keystorePath = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_FILE_PROPERTY, Folders.configuration() + File.separator + "envelope.p12");
        String keystorePasswordAlias = configuration.get(EnvelopeKeyManager.ENVELOPE_KEYSTORE_PASSWORD_PROPERTY, "envelope_keystore");
        Password keystorePassword = null;
        try (PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if (passwordVault.contains(keystorePasswordAlias)) {
                keystorePassword = passwordVault.get(keystorePasswordAlias);
            }
        }
        File keystoreFile = new File(keystorePath);
        if (keystoreFile.exists() && keystorePassword != null) {
            return new EnvelopeKeyManager(keystoreFile, keystorePassword.toCharArray());
        }
        throw new IllegalStateException("Envelope Key Manager not ready");
    }

    private SecretKey generateKey(String algorithm, int keyLengthBits) throws NoSuchAlgorithmException {
//        try {
        KeyGenerator kgen = KeyGenerator.getInstance(algorithm); // "AES"  // throws NoSuchAlgorithmException
        kgen.init(keyLengthBits);
        SecretKey skey = kgen.generateKey();
        return skey;
//        }
//        catch(NoSuchAlgorithmException e) {
//            throw new CryptographyException(e);
//        }
    }


    /**
     * Currently supports creating only AES keys
     *
     * @param createKeyRequest
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        log.debug("createKey");
//        Protection protection = ProtectionBuilder.factory().algorithm(createKeyRequest.algorithm).keyLengthBits(createKeyRequest.keyLength).mode("OFB8").build();
        ArrayList<Fault> faults = new ArrayList<>();
        try {
            // prepare a response with all the input attributes,
            // a new key id, and the default transfer policy
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
            /*  MOVED TO REMOTEKEYMANAGER */
            /*
            created.setKeyId(new UUID().toString());
            created.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
            created.setTransferLink(getTransferLinkForKeyId(created.getKeyId()));
            * */
            // create the key
            SecretKey skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());

            CipherKey cipherKey = new CipherKey();
            cipherKey.setAlgorithm(created.getAlgorithm());
            cipherKey.setKeyId(created.getKeyId());
            cipherKey.setKeyLength(created.getKeyLength());
            cipherKey.setMode(created.getMode());
            cipherKey.setEncoded(skey.getEncoded());
            cipherKey.setPaddingMode(created.getPaddingMode());
            cipherKey.set("transferPolicy", created.getTransferPolicy());
            cipherKey.set("transferLink", created.getTransferLink().toExternalForm());
            // store the key and its attributes
            log.debug("Storing cipher key {}", cipherKey.getKeyId());
            repository.store(created.getKeyId(), cipherKey);
            // TODO: encrypt the key using a storage key then write a PEM
            // file with the info. 
            log.info(KeyLogMarkers.CREATE_KEY, "Created key id: {}", cipherKey.getKeyId());

            CreateKeyResponse response = new CreateKeyResponse(created);
            return response;
            // wrap it with a storage key
        } catch (NoSuchAlgorithmException e) {
            log.debug("GenerateKey failed", e);
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("deleteKey");
        repository.delete(deleteKeyRequest.getKeyId());
        DeleteKeyResponse deleteKeyResponse = new DeleteKeyResponse();
        log.info(KeyLogMarkers.DELETE_KEY, "Deleted key id: {}", deleteKeyRequest.getKeyId());
        return deleteKeyResponse;
    }

    /** 
     * NOTE:  RETURNS PLAINTEXT KEY - CALLER MUST WRAP IT AS APPROPRIATE FOR
     * THE CURRENT CONTEXT.
     * @param keyRequest
     * @return 
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest keyRequest) {
        log.debug("transferKey");
        TransferKeyResponse response = new TransferKeyResponse();

        // load secret key from store
        CipherKey cipherKey = repository.retrieve(keyRequest.getKeyId());
        if (cipherKey == null) {
            response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
            return response;
        }
        try {
            log.debug("transferKey loaded key: {}", mapper.writeValueAsString(cipherKey));
            // XXX TODO hmm doesn' thave policy: urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization    even though it's shown by "createkey" respons.... probably the API layer is adding it, we need it in the backend !!
        } catch (Exception e) {
            log.error("transferKey loaded key but cannot serialize", e);
        }

        CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
        keyAttributes.copyFrom(cipherKey);
        
        response.setKey(cipherKey.getEncoded());
        response.setDescriptor(new KeyDescriptor());
        response.getDescriptor().setContent(keyAttributes);
        return response;
        
    }

//    @Override
    public KeyTransferPolicy getKeyPolicy(String keyId) {
        log.debug("getKeyPolicy");
        // TODO:   look up the policy.  at least the URI should be provided here,
        //         and maybe this API is not neeed at all since URI is in key attriutes.....   
        KeyTransferPolicy keyTransferPolicy = new KeyTransferPolicy();
        keyTransferPolicy.keyId = keyId;
        return keyTransferPolicy;
    }

    public static class PemKeyEncryptionFromRegisterKeyRequest implements PemKeyEncryption {

        private Pem pem;

        public PemKeyEncryptionFromRegisterKeyRequest(RegisterKeyRequest request) {
            pem = new Pem("ENCRYPTED KEY", request.getKey());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_ID_HEADER, request.getDescriptor().getContent().getKeyId());
            pem.setHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER, request.getDescriptor().getContent().getKeyLength() == null ? null : request.getDescriptor().getContent().getKeyLength().toString());
            pem.setHeader(KeyEnvelope.CONTENT_ALGORITHM_HEADER, request.getDescriptor().getContent().getAlgorithm());
            pem.setHeader(KeyEnvelope.CONTENT_MODE_HEADER, request.getDescriptor().getContent().getMode());
            pem.setHeader(KeyEnvelope.CONTENT_PADDING_MODE_HEADER, request.getDescriptor().getContent().getPaddingMode());
            pem.setHeader(KeyEnvelope.ENCRYPTION_KEY_ID_HEADER, request.getDescriptor().getEncryption().getKeyId());
            pem.setHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER, request.getDescriptor().getEncryption().getAlgorithm());
            pem.setHeader(KeyEnvelope.ENCRYPTION_MODE_HEADER, request.getDescriptor().getEncryption().getMode());
            pem.setHeader(KeyEnvelope.ENCRYPTION_PADDING_MODE_HEADER, request.getDescriptor().getEncryption().getPaddingMode());
        }

        @Override
        public String getContentKeyId() {
            return pem.getHeader(KeyEnvelope.CONTENT_KEY_ID_HEADER);
        }

        @Override
        public Integer getContentKeyLength() {
            return pem.getHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER) == null ? null : Integer.valueOf(pem.getHeader(KeyEnvelope.CONTENT_KEY_LENGTH_HEADER));
        }

        @Override
        public String getContentAlgorithm() {
            return pem.getHeader(KeyEnvelope.CONTENT_ALGORITHM_HEADER);
        }

        @Override
        public String getContentMode() {
            return pem.getHeader(KeyEnvelope.CONTENT_MODE_HEADER);
        }

        @Override
        public String getContentPaddingMode() {
            return pem.getHeader(KeyEnvelope.CONTENT_PADDING_MODE_HEADER);
        }

        @Override
        public Pem getDocument() {
            return pem;
        }

        @Override
        public boolean isEncrypted() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER) != null;
        }

        @Override
        public String getEncryptionKeyId() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_KEY_ID_HEADER);
        }

        @Override
        public String getEncryptionAlgorithm() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_ALGORITHM_HEADER);
        }

        @Override
        public String getEncryptionMode() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_MODE_HEADER);
        }

        @Override
        public String getEncryptionPaddingMode() {
            return pem.getHeader(KeyEnvelope.ENCRYPTION_PADDING_MODE_HEADER);
        }
    }

    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("registerKey");
        
        KeyDescriptor descriptor = registerKeyRequest.getDescriptor();
        CipherKey cipherKey = new CipherKey();
        if (descriptor != null && descriptor.getContent() != null) {
            cipherKey.setAlgorithm(descriptor.getContent().getAlgorithm());
            cipherKey.setKeyId(descriptor.getContent().getKeyId());
            cipherKey.setKeyLength(descriptor.getContent().getKeyLength());
            cipherKey.setMode(descriptor.getContent().getMode());
            cipherKey.setPaddingMode(descriptor.getContent().getPaddingMode());
            cipherKey.set("transferPolicy", descriptor.getContent().get("transferPolicy"));
            cipherKey.set("transferLink", descriptor.getContent().get("transferLink"));
        }

        if (cipherKey.getKeyId() == null) {
            cipherKey.setKeyId(new UUID().toString());
        }

        if (descriptor != null && descriptor.getEncryption() != null) {
            // key is encrypted
            PrivateKey encryptionPrivateKey = null;
            String encryptionPrivateKeyId = null;
            if (descriptor.getEncryption().getKeyId() != null) {
                // client specified one of our encryption public keys - try to load it
                try (EnvelopeKeyManager envelopeKeyManager = getEnvelopeKeyManager()) {
                    if (envelopeKeyManager.getKeystore().contains(descriptor.getEncryption().getKeyId())) {
                        encryptionPrivateKey = envelopeKeyManager.getKeystore().getPrivateKey(descriptor.getEncryption().getKeyId());
                        encryptionPrivateKeyId = descriptor.getEncryption().getKeyId();
                    }
                } catch (IOException | KeyStoreException e) {
                    log.error("Cannot register key", e);
                    RegisterKeyResponse response = new RegisterKeyResponse();
                    response.getFaults().add(new Fault("Cannot load encryption key"));
                }
            } else {
                // if the client did not specify an encryption key id, we can try 
                // either the last known encryption public key we sent them (if we
                // save that information) or the most recently created encryption public key
                // (if we have more than one) or the only encryption public key we have
            }

            if (encryptionPrivateKey != null) {
                // we found a matching private key, use it to unwrap the key sent by the client
                try {
                    PemKeyEncryptionFromRegisterKeyRequest pemKeyEncryption = new PemKeyEncryptionFromRegisterKeyRequest(registerKeyRequest);
                    RsaPublicKeyProtectedPemKeyEnvelopeOpener recipient = new RsaPublicKeyProtectedPemKeyEnvelopeOpener(encryptionPrivateKey, encryptionPrivateKeyId);
                    Key key = recipient.unseal(pemKeyEncryption);
                    cipherKey.setEncoded(key.getEncoded());
                } catch (CryptographyException e) {
                    log.error("Cannot load encryption private key to unwrap", e);
                    RegisterKeyResponse response = new RegisterKeyResponse();
                    response.getFaults().add(new Fault("Cannot load encryption key"));
                }
            } else {
                RegisterKeyResponse response = new RegisterKeyResponse();
                response.getFaults().add(new Fault("Cannot find encryption key"));
            }
        }


        // store the key and its attributes
        // TODO: encrypt the key using a storage key then write a PEM
        // file with the info. 
        repository.store(cipherKey.getKeyId(), cipherKey);


        KeyAttributes registered = new KeyAttributes();
        registered.copyFrom(cipherKey);
        log.info(KeyLogMarkers.REGISTER_KEY, "Registered key id: {}", cipherKey.getKeyId());
        RegisterKeyResponse response = new RegisterKeyResponse(registered);
        return response;
    }

//    @Override
    public void setKeyPolicy(String keyId, KeyTransferPolicy keyPolicy) {
        log.debug("setKeyPolicy");
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("searchKeyAttributes");
        SearchKeyAttributesResponse response = new SearchKeyAttributesResponse();
        File directory = new File(Folders.repository("keys"));
        String[] keyIds = directory.list();
        if( keyIds == null ) {
            log.warn("Unable to read keys directory");
        }
        else {
        for (String keyId : keyIds) {
            CipherKey key = repository.retrieve(keyId);
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(key);
            response.getData().add(keyAttributes);
        }
        }
        return response;

    }

    @Override
    public void configure(Configuration configuration) {
        log.debug("configure");
        this.configuration = configuration;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        log.debug("getKeyAttributes");
        CipherKey cipherKey = repository.retrieve(keyAttributesRequest.getKeyId());
        KeyAttributes attributes = new KeyAttributes();
        attributes.copyFrom(cipherKey);
        GetKeyAttributesResponse keyAttributesResponse = new GetKeyAttributesResponse();
        keyAttributesResponse.setData(attributes);
        return keyAttributesResponse;
    }

    /*
    private Configuration getConfiguration() {
        return configuration;
    }
    */
}
