/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

/**
 * Note the similarity between TransferKeyResponse and RegisterKeyRequest -
 * the difference is outgoing vs incoming.
 * 
 * @author jbuhacoff
 */
public class TransferKeyResponse extends AbstractResponse {
    
    /**
     * The key is encrypted in accordance with the descriptor
     */
    private byte[] key;
    
    /**
     * The descriptor contains either a plaintext key (rare) or an encrypted
     * key (typical) with encryption metadata, and possibly also integrity
     * metadata.
     */
    private KeyDescriptor descriptor;
    
    public TransferKeyResponse(byte[] key, KeyDescriptor descriptor) {
        this.key = key;
        this.descriptor = descriptor;
    }
    
    

    public byte[] getKey() {
        return key;
    }
    
    

    public KeyDescriptor getDescriptor() {
        return descriptor;
    }
    
    
}
