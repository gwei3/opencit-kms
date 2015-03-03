/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 * 
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class CreateKey extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(CreateKey.class);

    public CreateKey() {
        super();
    }
    
    /**
     * Request to create and store a new key. The algorithm and key length
     * must be specified in the {@code CreateKeyRequest} in JSON format.
     * 
     * Example request:
     * <pre>
     * POST /keys
     * Content-Type: application/json
     * Accept: application/json
     * 
     * {"algorithm": "AES","cipher_mode": "OFB","digest_algorithm": "SHA-256","key_length": "128","name": "key name","padding_mode": "","role": "key-encryption","transfer_policy": ""}
     * </pre>
     * 
     * Example response:
     * <pre>
     * Content-Type: application/json
     * 
     * {"attributes":{"id":"85a7a2b5-95b2-4fb3-96f2-f2618a485763","name":"key name","role":"key-encryption","algorithm":"AES","key_length":128,"cipher_mode":"OFB","padding_mode":"","digest_algorithm":"SHA-256","transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"}}
     * </pre>
     * 
     * @param createKeyRequest
     * @return 
     */
    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:create")    
    public CreateKeyResponse createKey(CreateKeyRequest createKeyRequest) {
        log.debug("CreateKey");
        CreateKeyResponse createKeyResponse = getKeyRepository().createKey(createKeyRequest);
        return createKeyResponse;
    }
}
