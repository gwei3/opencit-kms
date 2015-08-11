/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.api;

import com.intel.dcsg.cpg.io.Copyable;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import com.intel.mtwilson.util.crypto.key2.CipherKey;
import java.net.MalformedURLException;
import java.net.URL;

/**
 * 
 * @author jbuhacoff
 */
public class KeyAttributes extends CipherKeyAttributes implements Copyable {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(KeyAttributes.class);

    private String username;
    private String transferPolicy;
    private URL transferLink;
    
    /**
     * Optional user-provided description of the key.
     */
    private String description;
    
    /**
     * Optional user-provided role name indicates the use of the key.
     * For example:
     * data encryption, key encryption, signatures, key derivation
     */
    private String role;
    
    /**
     * Digest algorithm used in conjunction with this key. Optional.
     */
    private String digestAlgorithm;

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

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
    public String getTransferPolicy() {
        return transferPolicy;
    }

    public void setTransferPolicy(String transferPolicy) {
        this.transferPolicy = transferPolicy;
    }

    public URL getTransferLink() {
        return transferLink;
    }

    public void setTransferLink(URL transferLink) {
        this.transferLink = transferLink;
    }

    
    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }
    


    
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
        this.username = source.username;
        this.description = source.description;
        this.role = source.role;
        this.transferPolicy = source.transferPolicy;
        this.transferLink = source.transferLink;
    }
    
    public void copyFrom(CipherKey source) {
        this.setAlgorithm(source.getAlgorithm());
        this.setMode(source.getMode());
        this.setKeyLength(source.getKeyLength());
        this.setPaddingMode(source.getPaddingMode());
        this.setKeyId(source.getKeyId());
        
        if( source.get("transferPolicy")  != null ) {
            log.debug("copyFrom transferPolicy {}", source.get("transferPolicy"));
            this.setTransferPolicy((String)source.get("transferPolicy"));
        }
        if( source.get("transferLink") != null ) {
            log.debug("copyFrom transferLink {}", source.get("transferLink"));
            try {
            this.setTransferLink(new URL((String)source.get("transferLink")));
            }
            catch(MalformedURLException e) {
                log.error("Cannot set transfer policy for key", e);
            }
        }
//        this.name = null;
//        this.digestAlgorithm = null;
//        this.role = null;
//        this.transferPolicy = null;
    }
}
