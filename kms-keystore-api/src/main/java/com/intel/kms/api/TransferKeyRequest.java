/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Attributes;

/**
 * Transfer request is used by clients to retrieve a key.
 * 
 * In the future, additional fields may be added to allow the client to
 * specify the encryption and integrity algorithms it would prefer the
 * server use for protecting the key in transit - and the server will need
 * to choose among these a combination that the server supports and
 * satisfies the server's policy of protecting a key only with equivalent
 * or stronger cryptography.
 * 
 * @author jbuhacoff
 */
public class TransferKeyRequest extends Attributes {
    
    private String keyId;

    public TransferKeyRequest(String keyId) {
        this.keyId = keyId;
    }


    
    /**
     * Key ID to transfer
     * @return the requested key id
     */
    public String getKeyId() {
        return keyId;
    }


    
}
