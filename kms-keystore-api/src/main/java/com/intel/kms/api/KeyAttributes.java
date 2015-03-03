/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Copyable;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.CipherKey;

/**
 * 
 * @author jbuhacoff
 */
public class KeyAttributes extends CipherKeyAttributes implements Copyable {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyAttributes.class);

    /**
     * Unique identifier for the key (per tenant)
     */
    public String id;
    
    /**
     * Optional user-readable name for the key.
     */
    public String name;
    
    /**
     * Optional user-provided role name indicates the use of the key.
     * For example:
     * data encryption, key encryption, signatures, key derivation
     */
    public String role;
    
    /**
     * Digest algorithm used in conjunction with this key. Optional.
     */
    public String digestAlgorithm;
    

    /**
     * URI of a transfer policy to apply to this key.
     * The KMS requires a transfer policy for every key
     * but may support a default policy for new key
     * requests which omit this attribute and/or a global
     * (fixed) policy for all key requests (where
     * specifying the attribute would be an error because
     * it would be ignored). The policy itself is a
     * separate document that describes who may access
     * the key under what conditions (trusted, authenticated,
     * etc)
     * 
     * Example:
     * urn:intel:trustedcomputing:keytransferpolicy:trusted
     * might indicate that a built-in policy will enforce that
     * the key is only released to trusted clients, and
     * leave the definition of trusted up to the trust
     * attestation server. 
     * 
     * Example:
     * http://fileserver/path/to/policy.xml
     * might indicate that the fileserver has a file policy.xml
     * which is signed by this keyserver and contains the
     * complete key transfer policy including what is a trusted
     * client, what is the attestation server trusted certificate,
     * etc.
     * 
     */
    public String transferPolicy;
    
    @Override
    public KeyAttributes copy() {
        KeyAttributes newInstance = new KeyAttributes();
        newInstance.copyFrom(this);
        return newInstance;
    }
    
    public void copyFrom(KeyAttributes source) {
        super.copyFrom(source);
        log.debug("Copying algorithm {} from source", source.getAlgorithm());
        this.setAlgorithm(source.getAlgorithm());
        this.setMode(source.getMode());
        this.setKeyLength(source.getKeyLength());
        this.setPaddingMode(source.getPaddingMode());
        this.digestAlgorithm = source.digestAlgorithm;
        this.id = source.id;
        this.name = source.name;
        this.role = source.role;
        this.transferPolicy = source.transferPolicy;
    }
    
    public void copyFrom(CipherKey source) {
        this.setAlgorithm(source.getAlgorithm());
        this.setMode(source.getMode());
        this.setKeyLength(source.getKeyLength());
        this.setPaddingMode(source.getPaddingMode());
        this.id = source.getKeyId();
//        this.name = null;
//        this.digestAlgorithm = null;
//        this.role = null;
//        this.transferPolicy = null;
    }
}
