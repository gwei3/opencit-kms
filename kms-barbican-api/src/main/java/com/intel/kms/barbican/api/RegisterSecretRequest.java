/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.barbican.api;

/**
 * Represents message body for {@code POST v1/secrets}
 * 
 * https://github.com/cloudkeep/barbican/wiki/Application-Programming-Interface
 * 
 * @author jbuhacoff
 */
public class RegisterSecretRequest {
    public String name; // "AES key"
    public String expiration; // "2014-02-28T19:14:44.180394"
    public String algorithm; // "aes"
    public Integer bit_length; // 256
    public String mode; // "cbc"
    public String payload_content_type; // "application/octet-stream"
    public String payload_content_encoding ; // "application/octet-stream"
    public String secretType; // "opaque"
}
