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
import com.intel.mtwilson.configuration.PasswordVaultFactory;
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
import java.security.cert.CertificateException;

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
     *
     * @param createKeyRequest
     * @return a list of faults with the request, or an empty list if the
     * request is valid
     */
    private List<Fault> validateCreateKey(CreateKeyRequest createKeyRequest) {
        ArrayList<Fault> faults = new ArrayList<>();
        if (createKeyRequest.getAlgorithm() == null) {
            faults.add(new MissingRequiredParameter("algorithm"));
            return faults;
        }
        if (!createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            faults.add(new InvalidParameter("algorithm", new UnsupportedAlgorithm(createKeyRequest.getAlgorithm())));
            return faults;
        }
        // check AES specific parameters
        if (createKeyRequest.getAlgorithm().equalsIgnoreCase("AES")) {
            if (createKeyRequest.getKeyLength() == null) {
                faults.add(new MissingRequiredParameter("keyLength")); // TODO: the "parameter" field of the MissingRequiredParameter class needs to be annotated so a filter can automatically convert it's VALUE from keyLength to key_length (javascript) or keep it as keyLength (xml) or KeyLength (SAML) etc.  ... that's something the jackson mapper doesn't do so we have to ipmlement a custom filter for VALUES taht represent key names.
                return faults;
            }
            if (!ArrayUtils.contains(new int[]{128, 192, 256}, createKeyRequest.getKeyLength())) {
                faults.add(new InvalidParameter("keyLength"));
                return faults;
            }
        }
        return faults;
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
        ArrayList<Fault> faults = new ArrayList<>();
        faults.addAll(validateCreateKey(createKeyRequest));
        if (!faults.isEmpty()) {
            CreateKeyResponse response = new CreateKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }
//        Protection protection = ProtectionBuilder.factory().algorithm(createKeyRequest.algorithm).keyLengthBits(createKeyRequest.keyLength).mode("OFB8").build();
        try {
            // prepare a response with all the input attributes,
            // a new key id, and the default transfer policy
            KeyAttributes created = new KeyAttributes();
            created.copyFrom(createKeyRequest);
            created.setKeyId(new UUID().toString());
            created.setTransferPolicy("urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization");
            // create the key
            SecretKey skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());

            CipherKey cipherKey = new CipherKey();
            cipherKey.setAlgorithm(created.getAlgorithm());
            cipherKey.setKeyId(created.getKeyId());
            cipherKey.setKeyLength(created.getKeyLength());
            cipherKey.setMode(created.getMode());
            cipherKey.setEncoded(skey.getEncoded());
            cipherKey.setPaddingMode(created.getPaddingMode());
            // store the key and its attributes
            log.debug("Storing cipher key {}", cipherKey.getKeyId());
            repository.store(created.getKeyId(), cipherKey);
            // TODO: encrypt the key using a storage key then write a PEM
            // file with the info. 
            log.info(KeyLogMarkers.CREATE_KEY, "Created key id: {}", cipherKey.getKeyId());

            CreateKeyResponse response = new CreateKeyResponse(created);
            return response;
            // wrap it with a storage key
        } catch (NoSuchAlgorithmException ex) {
            log.debug("GenerateKey failed", ex);
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

    // NOTE: this is a rough first draft;  should refer to NIST 800-57 part 1, table 2 "comparable strengths" for more detailed recommendation on key lengths
    private boolean isProtectionAdequate(TransferKeyResponse response, CipherKeyAttributes subject, CipherKeyAttributes encryption) {
        // first, we allow protection using a key of the same algorithm of equal or greater length ( AES-128,192,256 can wrap AES-128,  RSA 1024,2048,4096 can wrap RSA 1024, etc.)
        if (subject.getAlgorithm().equals(encryption.getAlgorithm()) && subject.getKeyLength() <= encryption.getKeyLength()) {
            log.debug("Requested key algorithm {} same as encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        // check equivalent protection for other algorithm combinations; for now assume RSA 2048 is adequate to protect AES 128, 192, and 256
        // XXX TODO  NIST 800-57 table 2 recommends RSA 3072 or greater to provide 128 bits of security (to protect AES-128 keys) ... this may be an issue with RSA key sizes in TPM
        if (subject.getAlgorithm().equals("AES") && encryption.getAlgorithm().startsWith("RSA") && encryption.getKeyLength() >= 2048) {
            log.debug("Requested key algorithm {} different from encryption algorithm {} and key lengths ok subject {} <= encryption {}", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
            return true;
        }
        log.debug("Requested key algorithm {} encryption algorithm {} and key lengths subject {} <= encryption {} does not meet policy", subject.getAlgorithm(), encryption.getAlgorithm(), subject.getKeyLength(), encryption.getKeyLength());
        response.getFaults().add(new KeyTransferProtectionNotAcceptable(encryption.getAlgorithm(), encryption.getKeyLength()));
        // for now reject anything else
        return false;
    }

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

        CipherKeyAttributes recipientPublicKeyAttributes;
        RSAPublicKey recipientPublicKey;
        response.setDescriptor(new KeyDescriptor());

        // is the request for an authorized user or a trust-based key transfer?
        if (keyRequest.getUsername() == null) {
            log.debug("transferKey request for trust-based key transfer");
            // no username, so attempt trust-based
            // XXX the saml policy enforcement should be coming from a plugin, either kms-saml or another one, which will look for the "saml" attribute (extension) in the request object
            // the trust-based request must  include a SAML document; the kms-saml plugin stores it in the "saml" extended attribute
            log.debug("SAML: {}", keyRequest.get("saml"));

            try {
                // the kms-saml plugin puts these attributes here based on the SAML - but maybe this should be happening on "this side" but also via a plugin:
                recipientPublicKeyAttributes = (CipherKeyAttributes) keyRequest.get("recipientPublicKeyAttributes");
                try {
                    log.debug("transferKey recipient public key attributes: {}", mapper.writeValueAsString(recipientPublicKeyAttributes));
                } catch (Exception e) {
                    log.error("transferKey loaded recipient public key attributes but cannot serialize", e);
                }
                recipientPublicKey = (RSAPublicKey) keyRequest.get("recipientPublicKey");
                // the encrpytion attributes describe how the key is encrypted so that only the client can decrypt it
                CipherKeyAttributes tpmBindKeyAttributes = new CipherKeyAttributes();
                tpmBindKeyAttributes.setKeyId(Sha256Digest.digestOf(recipientPublicKey.getEncoded()).toHexString());
                tpmBindKeyAttributes.setAlgorithm("RSA");
                tpmBindKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength());
                tpmBindKeyAttributes.setMode("ECB");
                tpmBindKeyAttributes.setPaddingMode("OAEP-TCPA"); // OAEP with the 4 byte literal 'TCPA' as the padding parameter.

                // wrap the key; this is the content of cipher.key
                response.setKey(DataBind.bind(cipherKey.getEncoded(), recipientPublicKey));
                response.getDescriptor().setEncryption(tpmBindKeyAttributes);
            } catch (Exception e) {
                log.error("Cannot bind requested key", e);
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
        } else {
            log.debug("transferKey request for authorized user key transfer");
            // attempt by authorized user
            log.debug("Username: {}", keyRequest.getUsername());
            // do we have a registered public key for the user?
            UserRepository userRepository = new UserRepository();
            UserFilterCriteria criteria = new UserFilterCriteria();
            criteria.usernameEqualTo = keyRequest.getUsername();
            UserCollection userCollection = userRepository.search(criteria);
            if (userCollection.getUsers().isEmpty()) {
                // it is an error to request a transfer for a user that isn't registered; we log the specifics but we return simply "key not found" so that attackers cannot use this to discover registered usernames
                log.error("Username not found: {}", keyRequest.getUsername());
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
            if (userCollection.getUsers().size() > 1) {
                // it is an error to have multiple users registered under the same username
                log.error("Multiple users found for username: {}", keyRequest.getUsername());
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
            User user = userCollection.getUsers().get(0);
            try {
                if (user.getTransferKey() == null) {
                    // user does not have a transfer key registered, so policy must allow "plaintext" transfers to authorized user or else we deny the request
                    // XXX TODO
                    log.error("User does not have transfer key");
                    response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                    return response;
                } else {
                    recipientPublicKey = (RSAPublicKey) user.getTransferKey();
                    recipientPublicKeyAttributes = new CipherKeyAttributes();
//                    recipientPublicKeyAttributes.setAlgorithm(recipientPublicKey.getAlgorithm()); // this would be "RSA", but see below where we set it to the factory's algorithm "RSA/ECB/OAEP...."
                    recipientPublicKeyAttributes.setKeyId(keyRequest.getUsername());// XXX TODO  user's public key still needs an id...  we should be treating it like any other key.
                    recipientPublicKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength()); // we should just have this in metadata
//                    recipientPublicKeyAttributes.setKeyLength(envelope.geten);
                    /*
                     recipientPublicKeyAttributes.setAlgorithm(recipientPublicKey.getAlgorithm()); // "RSA"
                     recipientPublicKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength()); // for example, 2048
                     recipientPublicKeyAttributes.setMode("ECB"); // standard for wrapping a key with a public key since it's only one block
                     recipientPublicKeyAttributes.setPaddingMode("OAEPWithSHA-256AndMGF1Padding"); // see RsaPublicKeyProtectedPemKeyEnvelopeFactory
                     */

                    RsaPublicKeyProtectedPemKeyEnvelopeFactory factory = new RsaPublicKeyProtectedPemKeyEnvelopeFactory(recipientPublicKey, recipientPublicKeyAttributes.getKeyId()); 
                    SecretKey key = new SecretKeySpec(cipherKey.getEncoded(), cipherKey.getAlgorithm()); // algorithm like "AES"
                    PemKeyEncryption envelope = factory.seal(key);
                    
                    recipientPublicKeyAttributes.setAlgorithm(factory.getAlgorithm()); // "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"   or we could split it up and set algorithm, mode, and paddingmode separately on the encryption attributes
                    
                    response.setKey(envelope.getDocument().getContent());
                    response.getDescriptor().setEncryption(recipientPublicKeyAttributes);
                }
            } catch (CryptographyException | CertificateException e) {
                log.error("Cannot load transfer key for user: {}", keyRequest.getUsername(), e);
                response.getFaults().add(new KeyNotFound(keyRequest.getKeyId()));
                return response;
            }
        }

        // enforce policy: cannot wrap key with weaker key
        if (!isProtectionAdequate(response, cipherKey, recipientPublicKeyAttributes)) {
            //throw new IllegalArgumentException("Recipient key not adequate to protect secret key");
            return response;
        }


        try {
            // the key attributes of cipherKey but without the encoded key itself
            CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
            keyAttributes.copyFrom(cipherKey);
            response.getDescriptor().setContent(keyAttributes);

            // integrity protection on the encrypted key and its plaintext attributes.... use HMAC-SHA256 for 128-bit security  (see NIST 800-57 table 3) 
            // the two options are to use... 
            // 1) the cipher key itself as the HMAC key for HMAC-SHA-256, protecting its encrypted form and metadata, or 
            // 2) a key server private key to sign the encrypted form of the cipher key and the metadata.
            // For Mystery Hill specifically we know the clients will not have the key server's public key on hand,
            // so they wouldn't be able to verify the integrity using method #2. therefore we use the key itself with HMAC-SHA-256,
            // even though the key length recommendations for HMAC-SHA-256 is a 256-bit key (twice the size of the cipher key
            // which is likely to be 128 bits;  and if it was 256 bits then it would need HMAC-SHA-512 to protect and again it would
            // be half the appropriate length).
            // On the other hand, using the same key for integrity protection means an attacker could replace the entire package 
            // (encrypted secret key and its metadata and integrity signature) but unlikely that an attacker can tamper with just the metadata.
            IntegrityKeyAttributes integrityKeyAttributes = new IntegrityKeyAttributes();
            integrityKeyAttributes.setAlgorithm("HMAC-SHA256");
            integrityKeyAttributes.setKeyId(keyRequest.getKeyId()); // indicate we're using the same cipher key to generate the HMAC
            integrityKeyAttributes.setKeyLength(cipherKey.getKeyLength());
            integrityKeyAttributes.setManifest(Arrays.asList("cipher.key", "cipher.json"));
            integrityKeyAttributes.set("signature", "integrity.sig"); // indicates in which file we are storing the HMAC signature;  we need to put it either here or in the links
            response.getDescriptor().setIntegrity(integrityKeyAttributes);

            // add links in the descriptor to the other content
            ArrayList<Link> links = new ArrayList<>();
            links.add(Link.build().rel("content").href("cipher.key").type("application/octet-stream"));
            links.add(Link.build().rel("content-descriptor").href("cipher.json").type("application/json"));
            links.add(Link.build().rel("signature").href("integrity.sig").type("application/octet-stream"));
            response.getDescriptor().set("links", links);

            // create cipher.json
            String cipherJson = mapper.writeValueAsString(response.getDescriptor()); // describes the cipher key and its encryption/integrity information but does not include the cipher key itself 

            // create integrity.sig
            byte[] document = ByteArray.concat(cipherKey.getEncoded(), cipherJson.getBytes(Charset.forName("UTF-8"))); // this is what we're signing: the encrypted key + the metadata
            byte[] signature = hmacSha256(cipherKey.getEncoded(), document);

            // add the serialized json because that's what was actually signed; this prevents any issue with slightly different serialization by the caller
            response.getExtensions().set("cipher.key", response.getKey());
            response.getExtensions().set("cipher.json", cipherJson);
            response.getExtensions().set("integrity.sig", signature);

            log.info(KeyLogMarkers.TRANSFER_KEY, "Transferred key id: {}", keyRequest.getKeyId());
            return response;
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalArgumentException("Unable to bind key", e);
        }
    }

    private byte[] hmacSha256(byte[] key, byte[] document) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256"); // throws NoSuchAlgorithmException
        mac.init(keySpec); // throws InvalidKeyException
        return mac.doFinal(document);

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
        for (String keyId : keyIds) {
            CipherKey key = repository.retrieve(keyId);
            KeyAttributes keyAttributes = new KeyAttributes();
            keyAttributes.copyFrom(key);
            response.getData().add(keyAttributes);
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

    private Configuration getConfiguration() {
        return configuration;
    }
}
