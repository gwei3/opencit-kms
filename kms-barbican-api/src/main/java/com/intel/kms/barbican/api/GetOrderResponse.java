/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

/**
 *
 * @author jbuhacoff
 */
public class GetOrderResponse {
    public String type; // "key"
    public RegisterSecretRequest meta; // Secret parameters provided in the original order request
    public String orderRef; // URL "http://localhost:8080/v1/orders/f9b633d8-fda5-4be8-b42c-5b2c9280289e"
    public String secretRef; // URL "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718"
    public String status; // "ERROR" or "ACTIVE"
    public String statusErrorCode; // "400 Bad Request"
    public String statusReason; // "Secret creation issue seen - content-encoding of 'bogus' not supported."
}
