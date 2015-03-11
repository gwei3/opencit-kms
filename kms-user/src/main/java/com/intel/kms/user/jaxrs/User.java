/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user.jaxrs;

import com.intel.kms.user.Contact;
import com.intel.mtwilson.jaxrs2.AbstractDocument;

/**
 *
 * @author jbuhacoff
 */
public class User extends AbstractDocument {
    private String username;
    private Contact contact;
    private String transferKeyPem;

    /**
     * Username is used for logging in to the service. 
     * @return 
     */
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    
    
    /**
     * Contact information for the user includes first name, last name, and
     * email address. 
     * @return 
     */
    public Contact getContact() {
        return contact;
    }

    public void setContact(Contact contact) {
        this.contact = contact;
    }

    /**
     * The transfer key is used to wrap keys sent to the user. It is also
     * known as the user's Key Encryption Key (KEK).
     * Here the transfer key is represented in PEM format like this:
     * <pre>
     * -----BEGIN PUBLIC KEY-----
     * (base64 data here)
     * -----END PUBLIC KEY-----
     * </pre>
     *
     * @return 
     */
    public String getTransferKeyPem() {
        return transferKeyPem;
    }

    public void setTransferKeyPem(String transferKeyPem) {
        this.transferKeyPem = transferKeyPem;
    }

    
        
}
