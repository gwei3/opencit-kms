/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.user;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.validation.Regex;
import com.intel.dcsg.cpg.validation.Unchecked;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.jaxrs2.AbstractDocument;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
    @Regex("[\\r\\n]*-{5}[a-zA-Z0-9 ]+-{5}[\\r\\n]+[a-zA-Z0-9/.=+\\r\\n]+[\\r\\n]+-{5}[a-zA-Z0-9 ]+-{5}[\\r\\n]*")
    public String getTransferKeyPem() {
        return transferKeyPem;
    }

    public void setTransferKeyPem(String transferKeyPem) {
        this.transferKeyPem = transferKeyPem;
    }

    
    /**
     * The transfer key is used to wrap keys sent to the user. It is also
     * known as the user's Key Encryption Key (KEK). 
     * 
     * @return 
     */
    @JsonIgnore
    @Unchecked
    public PublicKey getTransferKey() throws CryptographyException, CertificateException {
        if( transferKeyPem == null ) { return null; }
        if( transferKeyPem.startsWith("-----BEGIN CERTIFICATE-----")) {
            return X509Util.decodePemCertificate(transferKeyPem).getPublicKey();
        }
        else {
            return RsaUtil.decodePemPublicKey(transferKeyPem);
        }
    }

    @JsonIgnore
    public void setTransferKey(PublicKey transferKey) {
        this.transferKeyPem = RsaUtil.encodePemPublicKey(transferKey);
    }
    @JsonIgnore
    public void setTransferKey(X509Certificate transferKey) throws CertificateEncodingException {
        this.transferKeyPem = X509Util.encodePemCertificate(transferKey);
    }
        
}
