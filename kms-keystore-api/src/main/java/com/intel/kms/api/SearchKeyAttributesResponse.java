/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayList;
import java.util.Collection;

//    @JacksonXmlRootElement(localName="host_attestation_collection")

public class SearchKeyAttributesResponse {
    // jackson 2.0
    @JsonInclude(value = JsonInclude.Include.ALWAYS)
//    @JacksonXmlElementWrapper(localName = "search_results")
//    @JacksonXmlProperty(localName = "search_results")
    public Collection<KeyAttributes> searchResults = new ArrayList<>();
    
}
