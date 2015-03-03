/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.KeyTransferPolicy;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
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
public class SetKeyPolicy extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SetKeyPolicy.class);

    public SetKeyPolicy() {
        super();
    }

    
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/key-policy")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:set_attributes")    
    public void setKeyPolicy(@PathParam("keyId") String keyId, KeyTransferPolicy keyPolicy) {
        log.debug("SetKeyPolicy");        
        getKeyRepository().setKeyPolicy(keyId, keyPolicy);
    }
}
