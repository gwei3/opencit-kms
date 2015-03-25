/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import javax.ws.rs.HeaderParam;

/**
 * Represents reques to {@code POST /v1/orders}
 * 
 * @author jbuhacoff
 */
public class CreateOrderRequest {
    @HeaderParam("X-Project-Id")
    public String projectId; // from header X-Project-Id: {project_id}

    public String type; // "key"
    public RegisterSecretRequest meta;
}
