/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.KeyTransferPolicy;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class GetKeyPolicy extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GetKeyPolicy.class);

    public GetKeyPolicy() {
        super();
    }

    
    @GET
    @Path("/{keyId: [0-9a-zA-Z_-]+}/key-policy")
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:view_attributes")    
    public KeyTransferPolicy getKeyPolicy(@PathParam("keyId") String keyId) {
        log.debug("GetKeyPolicy");
        return getKeyRepository().getKeyPolicy(keyId);        
    }
}
