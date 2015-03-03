/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import org.apache.shiro.authz.annotation.RequiresPermissions;
/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class TransferKey extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TransferKey.class);

    public TransferKey() {
        super();
    }

    /**
     * Only authorized key owners can retrieve a key using their login 
     * credentials. This API is not available to non-authenticated clients.
     * 
     * Example request:
     * <pre>
     * POST /keys/85a7a2b5-95b2-4fb3-96f2-f2618a485763
     * </pre>
     * 
     * Example response:
     * <pre>
     * {"key":"base64-key-here","protection":{"encryption":{"algorithm":"AES","key_length":128},"integrity":{"digest_algorithm":"SHA-256"}}}
     * </pre>
     * 
     * @param keyId
     * @param keyRequest
     * @return 
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:transfer")
    public TransferKeyResponse getKey(@PathParam("keyId") String keyId /*, TransferKeyRequest keyRequest*/) {
        log.debug("GetKey");
        TransferKeyRequest keyRequest = new TransferKeyRequest(keyId);
        return getKeyRepository().transferKey(keyRequest);
    }

}
