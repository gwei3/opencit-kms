/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

import java.util.Map;

/**
 *
 * @author jbuhacoff
 */
public class GetSecretResponse {
    public String status; // "ACTIVE"
    public String secretType; // "symmetric"
    public String updated; // "2013-06-28T15:23:33.092660"
    public String name; // "AES key"
    public String algorithm; // "AES"
    public String mode; // "cbc"
    public Integer bitLength; // 256
    public Map<String,String> contentTypes; // { default: "application/octet-stream" }
    public String expiration; // "2013-05-08T16:21:38.134160"
    public String secretRef; // URL "http://localhost:8080/v1/secrets/888b29a4-c7cf-49d0-bfdf-bd9e6f26d718"
}
