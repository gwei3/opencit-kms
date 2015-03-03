/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.dcsg.cpg.io.Attributes;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.dcsg.cpg.validation.Faults;
import com.intel.mtwilson.collection.MultivaluedHashMap;
import com.intel.mtwilson.jaxrs2.Link;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public abstract class AbstractResponse extends Attributes implements Faults {

    private final HttpResponse httpResponse = new HttpResponse();
    
    @JsonIgnore
    public HttpResponse getHttpResponse() { return httpResponse; }
    
    
    public static class HttpResponse {
        private Integer status = null;
        private final MultivaluedHashMap<String,String> headers = new MultivaluedHashMap<>();

        public Integer getStatusCode() {
            return status;
        }

        public MultivaluedHashMap<String, String> getHeaders() {
            return headers;
        }

        public void setStatusCode(Integer statusCode) {
            this.status = statusCode;
        }
        
    }
    
    /**
     * On success, there could be links to relevant information,
     * such as a rel:created link for created keys, 
     * or rel:registered link for registered keys.
     */
    private final List<Link> links = new ArrayList<>();
    
    /**
     * On failure, there should be one or more faults here
     * detailing what went wrong.
     */
    private final List<Fault> faults = new ArrayList<>();
    
    public List<Link> getLinks() { return links; }
    
    @Override
    public List<Fault> getFaults() { return faults; }
    
}
