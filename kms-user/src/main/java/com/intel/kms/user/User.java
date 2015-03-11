/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user;

import java.security.PublicKey;

/**
 *
 * @author jbuhacoff
 */
public class User {
    private String username;
    private Contact contact;
    private PublicKey transferKey;

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
     * 
     * @return 
     */
    public PublicKey getTransferKey() {
        return transferKey;
    }

    public void setTransferKey(PublicKey transferKey) {
        this.transferKey = transferKey;
    }
    
    
}
