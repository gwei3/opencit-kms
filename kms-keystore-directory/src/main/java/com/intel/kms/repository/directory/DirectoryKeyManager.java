/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.repository.directory;

import com.intel.kms.api.KeyDescriptor;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.dcsg.cpg.configuration.Configurable;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.Sha256Digest;
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
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.jaxrs2.provider.JacksonObjectMapperProvider;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.Protection;
import com.intel.mtwilson.util.tpm12.DataBind;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
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

    public DirectoryKeyManager() {
        keysDirectory = new File(Folders.repository("keys"));
        if (!keysDirectory.exists()) {
            if (!keysDirectory.mkdirs()) {
                log.error("Cannot create keys directory");
            }
        }
        mapper = JacksonObjectMapperProvider.createDefaultMapper();
        repository = new JacksonFileRepository<>(keysDirectory);
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
            created.id = new UUID().toString();
            created.transferPolicy = "urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization";
            // create the key
            SecretKey skey = generateKey(createKeyRequest.getAlgorithm(), createKeyRequest.getKeyLength());

            CipherKey cipherKey = new CipherKey();
            cipherKey.setAlgorithm(created.getAlgorithm());
            cipherKey.setKeyId(created.id);
            cipherKey.setKeyLength(created.getKeyLength());
            cipherKey.setMode(created.getMode());
            cipherKey.setEncoded(skey.getEncoded());
            cipherKey.setPaddingMode(created.getPaddingMode());
            // store the key and its attributes
            log.debug("Storing cipher key {}", cipherKey.getKeyId());
            repository.store(created.id, cipherKey);
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
    private boolean isProtectionAdequate(CipherKeyAttributes subject, CipherKeyAttributes encryption) {
        // first, we allow protection using a key of the same algorithm of equal or greater length ( AES-128,192,256 can wrap AES-128,  RSA 1024,2048,4096 can wrap RSA 1024, etc.)
        if( subject.getAlgorithm().equals(encryption.getAlgorithm()) && subject.getKeyLength() <= encryption.getKeyLength() ) {
            return true;
        }
        // check equivalent protection for other algorithm combinations; for now assume RSA 2048 is adequate to protect AES 128, 192, and 256
        // XXX TODO  NIST 800-57 table 2 recommends RSA 3072 or greater to provide 128 bits of security (to protect AES-128 keys) ... this may be an issue with RSA key sizes in TPM
        if( subject.getAlgorithm().equals("AES") && encryption.getAlgorithm().equals("RSA") && encryption.getKeyLength() >= 2048 ) {
            return true;
        } 
        // for now reject anything else
        return false;
    }

    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest keyRequest) {
        log.debug("getKey");
        
        CipherKeyAttributes recipientPublicKeyAttributes = (CipherKeyAttributes)keyRequest.get("recipientPublicKeyAttributes");
        RSAPublicKey recipientPublicKey = (RSAPublicKey)keyRequest.get("recipientPublicKey");
        
        // load secret key from store
        CipherKey cipherKey = repository.retrieve(keyRequest.getKeyId());
        
        // enforce policy: cannot wrap key with weaker key
        if( !isProtectionAdequate(cipherKey, recipientPublicKeyAttributes) ) {
            throw new IllegalArgumentException("Recipient key not adequate to protect secret key");
        }
        
        try {
            // the encrpytion attributes describe how the key is encrypted so that only the client can decrypt it
            CipherKeyAttributes tpmBindKeyAttributes = new CipherKeyAttributes();
            tpmBindKeyAttributes.setKeyId(Sha256Digest.digestOf(recipientPublicKey.getEncoded()).toHexString());
            tpmBindKeyAttributes.setAlgorithm("RSA");
            tpmBindKeyAttributes.setKeyLength(recipientPublicKey.getModulus().bitLength());
            tpmBindKeyAttributes.setMode("ECB");
            tpmBindKeyAttributes.setPaddingMode("OAEP-TCPA"); // OAEP with the 4 byte literal 'TCPA' as the padding parameter.

            // wrap the key; this is the content of cipher.key
            byte[] encryptedKey = DataBind.bind(cipherKey.getEncoded(), recipientPublicKey);
            
            // prepare metadata object to describe to the client what we are returning
            KeyDescriptor descriptor = new KeyDescriptor();

            // the key attributes of cipherKey but without the encoded key itself
            CipherKeyAttributes keyAttributes = new CipherKeyAttributes();
            keyAttributes.copyFrom(cipherKey);

            descriptor.setContent(keyAttributes);
            descriptor.setEncryption(tpmBindKeyAttributes);
            
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
            descriptor.setIntegrity(integrityKeyAttributes);
            
            // add links in the descriptor to the other content
            ArrayList<Link> links = new ArrayList<>();
            links.add(Link.build().rel("content").href("cipher.key").type("application/octet-stream"));
            links.add(Link.build().rel("content-descriptor").href("cipher.json").type("application/json"));
            links.add(Link.build().rel("signature").href("integrity.sig").type("application/octet-stream"));
            descriptor.set("links", links);
            
            // create cipher.json
            String cipherJson = mapper.writeValueAsString(descriptor); // describes the cipher key and its encryption/integrity information but does not include the cipher key itself 
            
            // create integrity.sig
            byte[] document = ByteArray.concat(cipherKey.getEncoded(), cipherJson.getBytes(Charset.forName("UTF-8"))); // this is what we're signing: the encrypted key + the metadata
            byte[] signature = hmacSha256(cipherKey.getEncoded(), document);

            // create the response object
            TransferKeyResponse response = new TransferKeyResponse(encryptedKey, descriptor);
            // add the serialized json because that's what was actually signed; this prevents any issue with slightly different serialization by the caller
            response.getExtensions().set("cipher.key", encryptedKey);
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

    @Override
    public KeyAttributes getKeyAttributes(String keyId) {
        log.debug("getKeyAttributes");
        CipherKey cipherKey = repository.retrieve(keyId);
        KeyAttributes attributes = new KeyAttributes();
        attributes.copyFrom(cipherKey);
//        attributes.id = keyId;
        return attributes;
    }

    @Override
    public KeyTransferPolicy getKeyPolicy(String keyId) {
        log.debug("getKeyPolicy");
        // TODO:   look up the policy.  at least the URI should be provided here,
        //         and maybe this API is not neeed at all since URI is in key attriutes.....   
        KeyTransferPolicy keyTransferPolicy = new KeyTransferPolicy();
        keyTransferPolicy.keyId = keyId;
        return keyTransferPolicy;
    }

    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("registerKey");
        // TODO:  look up private key whose corresponding public key is specified in envelope 
        //        decrypt envelope using ouir private key
        CipherKey cipherKey = new CipherKey();
        cipherKey.setAlgorithm(registerKeyRequest.getDescriptor().getContent().getAlgorithm());
        cipherKey.setKeyId(new UUID().toString()); // registerKeyRequest.attributes.id.getBytes(Charset.forName("UTF-8"));
        cipherKey.setKeyLength(registerKeyRequest.getDescriptor().getContent().getKeyLength());
        cipherKey.setMode(registerKeyRequest.getDescriptor().getContent().getMode());
//            cipherKey.encoded = registerKeyRequest.key; // TDODO  .... XXXX X   NEED TO UNWRAP FIRST
        cipherKey.setPaddingMode(registerKeyRequest.getDescriptor().getContent().getPaddingMode());
        // store the key and its attributes
        repository.store(registerKeyRequest.getDescriptor().getContent().getKeyId(), cipherKey);

        
        KeyAttributes registered = new KeyAttributes();
        registered.copyFrom(registerKeyRequest.getDescriptor());
        registered.set("keyId", cipherKey.getKeyId());
        // TODO: encrypt the key using a storage key then write a PEM
        // file with the info. 
        log.info(KeyLogMarkers.REGISTER_KEY, "Registered key id: {}", cipherKey.getKeyId());
        RegisterKeyResponse response = new RegisterKeyResponse(registered);
        return response;
    }

    @Override
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
}
