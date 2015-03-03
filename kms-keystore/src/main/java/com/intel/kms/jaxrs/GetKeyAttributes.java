/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.kms.api.KeyAttributes;
import com.intel.mtwilson.jaxrs2.Link;
import com.intel.mtwilson.launcher.ws.ext.V2;
import java.util.ArrayList;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.authz.annotation.RequiresPermissions;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class GetKeyAttributes extends AbstractEndpoint {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(GetKeyAttributes.class);

    public GetKeyAttributes() {
        super();
    }

    
    /**
     * Example request:
     * <pre>
     * GET /keys/85a7a2b5-95b2-4fb3-96f2-f2618a485763
     * Accept: application/json
     * </pre>
     * 
     * Example response:
     * <pre>
     * Content-Type: application/json
     * 
     * {
     * "algorithm":"AES",
     * "key_length":128,
     * "id":"3787f629-1827-411e-866e-ce87e37f805a",
     * "links":[{"rel":"transfer","href":"/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer","type":"application/octet-stream","accept_post":"application/x-pem-file, application/saml+xml"},{"rel":"transfer","href":"/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer","type":"application/x-pem-file","accept_post":"application/x-pem-file, application/saml+xml"},{"rel":"transfer","href":"/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer","type":"archive/tar+gzip","accept_post":"application/x-pem-file, application/saml+xml"}]
     * }
     * </pre>
     * 
     * @param keyId
     * @return 
     */
    @GET
    @Path("/{keyId: [0-9a-zA-Z_-]+}")
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:get_attributes")    
    public KeyAttributes getKeyAttributes(@PathParam("keyId") String keyId, @Context HttpServletRequest request) {
        log.debug("GetKeyAttributes");
        
        log.debug("Method: {}", request.getMethod());
        log.debug("Scheme: {}", request.getScheme());
        log.debug("RequestURL: {}", request.getRequestURL());
        log.debug("RequestURI: {}", request.getRequestURI());
        log.debug("ServerName: {}", request.getServerName());
        log.debug("ServerPort: {}", request.getServerPort());
        log.debug("ContextPath: {}", request.getContextPath());
        log.debug("PathInfo: {}", request.getPathInfo());
        log.debug("PathTranslated: {}", request.getPathTranslated());
        log.debug("RemoteAddr: {}", request.getRemoteAddr());
        log.debug("ServletPath: {}", request.getServletPath());
        
        KeyAttributes attributes = getKeyRepository().getKeyAttributes(keyId);
        ArrayList<Link> links = new ArrayList<>();
        links.add(Link.build().rel("transfer").href(String.format("%s/transfer", request.getPathInfo())).type("application/octet-stream").acceptPost("application/x-pem-file, application/saml+xml"));
        links.add(Link.build().rel("transfer").href(String.format("%s/transfer", request.getPathInfo())).type("application/x-pem-file").acceptPost("application/x-pem-file, application/saml+xml"));
        links.add(Link.build().rel("transfer").href(String.format("%s/transfer", request.getPathInfo())).type("archive/tar+gzip").acceptPost("application/x-pem-file, application/saml+xml"));
        attributes.set("links", links);
        return attributes;
    }
}
