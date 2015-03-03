/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.DELETE;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.core.Context;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class DeleteKey extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(DeleteKey.class);

    public DeleteKey() {
        super();
    }

    /**
     * Example request:
     * <pre>
     * DELETE /keys/85a7a2b5-95b2-4fb3-96f2-f2618a485763
     * </pre>
     * 
     * Example response:
     * <pre>
     * 200 OK
     * 
     * {"links":[{"rel":"search","href":"/v1/keys"]}
     * </pre>
     * @param keyId 
     */
    @DELETE
    @Path("/{keyId: [0-9a-zA-Z_-]+}")
//    @Consumes(MediaType.APPLICATION_JSON)
//    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:delete")    
    public DeleteKeyResponse deleteKey(@PathParam("keyId") String keyId, @Context HttpServletRequest request) {
        log.debug("DeleteKey");
        DeleteKeyResponse response = getKeyRepository().deleteKey(new DeleteKeyRequest(keyId));
        response.getLinks().add(new Link("search", String.format("%s/keys", request.getServletPath())));
        return response;
        /*
        if( response.faults != null && !response.faults.isEmpty() ) {
            log.error("Failed to delete key: {}", keyId);
        }
        */
//        log.debug("DeleteKey completed with {} faults", response.faults.size());
    }
}
