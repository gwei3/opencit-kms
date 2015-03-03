/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.KeyDescriptor;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.IntegrityKeyAttributes;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 * In contrast to CreateKey which consumes a JSON request asking the server to
 * create a key with specified algorithm and key length, RegisterKey lets the
 * caller send an existing key in one of several formats. Because CreateKey
 * consumes application/json, RegisterKey cannot also consume application/json
 * or it would conflict. However, JSON can still be used to send keys by
 * formatting them in accordance with the JSON Web Keys specification (JWK) and
 * sending a content type of application/jwk+json.
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class RegisterKey extends AbstractEndpoint {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(RegisterKey.class);

    public RegisterKey() {
        super();
    }

    /**
     * Provide the existing key in JSON Web Key format.
     *
     * @param registerKeyRequest
     * @return
     */
    @POST
    @Consumes("application/jwk+json")
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:register")
    public RegisterKeyResponse registerKeyJWK(RegisterKeyRequest registerKeyRequest) {
        log.debug("RegisterKey JWK");
        return getKeyRepository().registerKey(registerKeyRequest);
    }

    /**
     * Register an existing key in PEM format.
     *
     * Example request:
     * <pre>
     * POST /keys
     * Content-Type: application/x-pem-file
     *
     * -----BEGIN SECRET KEY-----
     * EnvelopeKeyId: sha256-of-public-key-in-hex
     * EnvelopeAlgorithm: RSA
     * ContentAlgorithm: AES
     * 
     * (base64 encoded data here, the AES key encrypted by the RSA key)
     * -----END SECRET KEY-----
     * </pre>
     *
     * Example response:
     *
     *
     * @param registerKeyRequest
     * @return
     */
    @POST
    @Consumes(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:register")
    public RegisterKeyResponse registerKeyPEM(String pemText) {
        log.debug("RegisterKey PEM");
//        Pem pem = Pem.valueOf(pemText);
        RsaKeyEnvelope pem = RsaKeyEnvelope.fromPem(pemText);
        
        CipherKeyAttributes contentAttributes = new CipherKeyAttributes();
        // prototype used a header "ContentKeyId" to give an id to the key
        contentAttributes.setKeyId(pem.getHeader("ContentKeyId"));
        contentAttributes.setAlgorithm(pem.getContentAlgorithm());
        // prototype assumed kms has a single recipient key and it wraps
        // the content key with that. so unless there is a recipient header,
        // we just use our default recipient key.
        CipherKeyAttributes encryptionAttributes = new CipherKeyAttributes();
        encryptionAttributes.setAlgorithm(pem.getEnvelopeAlgorithm());
        encryptionAttributes.setKeyId(pem.getEnvelopeKeyId());
        // if the envelope has integrity attributes we could grab those too
        IntegrityKeyAttributes integrityAttributes = new IntegrityKeyAttributes();
        
        byte[] key = null; // TODO: result of decrypting the pem content
        KeyDescriptor descriptor = new KeyDescriptor();
        descriptor.setContent(contentAttributes);
        descriptor.setEncryption(encryptionAttributes);
        descriptor.setIntegrity(integrityAttributes);
        
        RegisterKeyRequest registerKeyRequest = new RegisterKeyRequest();
        registerKeyRequest.setKey(key);
        registerKeyRequest.setDescriptor(descriptor);
        return getKeyRepository().registerKey(registerKeyRequest);
    }
}
