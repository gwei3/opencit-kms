/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.ws.v2.api;

import com.intel.dcsg.cpg.validation.Regex;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

/**
 *
 * @author jbuhacoff
 */
public class Key extends AbstractDocument {
    private String algorithm;
    private Integer keyLength;
    private String mode;
    private String paddingMode;
    private String username;
    private String transferPolicy;
    private String description;
    private String role;
    private String digestAlgorithm;

    @Regex("[a-zA-Z0-9_-]+")
    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    @Regex("[a-zA-Z0-9_-]+")
    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getPaddingMode() {
        return paddingMode;
    }

    public void setPaddingMode(String paddingMode) {
        this.paddingMode = paddingMode;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Regex("[a-zA-Z0-9/,:_-]*")
    public String getTransferPolicy() {
        return transferPolicy;
    }

    public void setTransferPolicy(String transferPolicy) {
        this.transferPolicy = transferPolicy;
    }

    public String getDescription() {
        return description;
    }

    @Regex("[a-zA-Z0-9 \\r\\n/,:_-]*")
    public void setDescription(String description) {
        this.description = description;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    @Regex("[a-zA-Z0-9_-]*")
    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    
}
