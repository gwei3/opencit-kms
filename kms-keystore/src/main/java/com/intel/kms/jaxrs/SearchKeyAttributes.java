/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.mtwilson.launcher.ws.ext.V2;
import javax.ws.rs.BeanParam;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 * TENTATIVE because this is related to key management which the user can
 * get from the backend key server directly.
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class SearchKeyAttributes extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SearchKeyAttributes.class);

    public SearchKeyAttributes() {
        super();
    }

    /**
     * Example request:
     * <pre>
     * GET /keys?algorithm=AES&key_length=128&cipher_mode=OFB
     * Accept: application/json
     * </pre>
     * 
     * Example response:
     * <pre>
     * Content-Type: application/json
     * 
     * {
     *   search_results: [
     *     {"id":"85a7a2b5-95b2-4fb3-96f2-f2618a485763","algorithm":"AES","key_length":128,"cipher_mode":"OFB"},
     *     {"id":"a2d6c172-85ae-4fb3-96f2-a17ce2df1c92","algorithm":"AES","key_length":128,"cipher_mode":"OFB"}
     *   ]
     * }
     * </pre>
     * @param criteria
     * @return 
     */
    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:search")    
    public SearchKeyAttributesResponse searchKeyAttributes(@BeanParam SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("GetKeyAttributes");
        SearchKeyAttributesResponse createKeyResponse = getKeyRepository().searchKeyAttributes(searchKeyAttributesRequest);
        return createKeyResponse;
    }
}
