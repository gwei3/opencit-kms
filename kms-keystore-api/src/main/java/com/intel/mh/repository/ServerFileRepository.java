/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaCredentialX509;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelopeRecipient;
import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelopeRecipient;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.dcsg.cpg.io.file.FileRepository;
import java.io.File;
import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public class ServerFileRepository {
    private final String path;
    private FileRepository privateKeys;  // the server's key management private keys (clients encrypt dek's using the corresponding certificates)
    private FileRepository userKeys;  // the dek's that users send for management
    /**
     * 
     * @param path for example System.getProperty("user.home") + File.separator + ".mystery-hill"
     */
    public ServerFileRepository(String path) {
        this.path = path;
    }
    
    /**
     * MHKeyMgmtSvc stores password-encrypted RSA credentials here (clients encrypt dek's with corresponding certificates)
     * @return 
     */
    public String getPrivateKeyPath() { return path + File.separator + "private"; }

    /**
     * MHKeyMgmtSvc stores RSA-encrypted DEK's here (received from MHClient)
     * @return 
     */
    public String getUserKeyPath() { return path + File.separator + "user"; }
    
    
    public String getMtWilsonClientKeystorePath() { return path + File.separator + "mtwilson.jks"; }
    
    /**
     * Post-condition:  the member variables dekFolder, recipientFolder, privateKeyFolder point to existing directories
     */
    public void open() {
        // create all necessary directories
        privateKeys = new FileRepository(getPrivateKeyPath());
        privateKeys.open();
        userKeys = new FileRepository(getUserKeyPath());
        userKeys.open();
    }
    
    public void close() {
        privateKeys.close();
        userKeys.close();
    }
    
    ///////////////////////////////////////////// Private keys that can be used to receive wrapped data encryption keys

//    @Override
    public void addPrivateKey(String alias, PasswordKeyEnvelope privateKey, X509Certificate recipient) throws IOException {
        try {
            privateKeys.add(alias, privateKey.toPem());
            privateKeys.add(alias+".crt", recipient.getEncoded());
        }
        catch(CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

//    @Override
    public void removePrivateKey(String alias) throws IOException {
        privateKeys.remove(alias);
        privateKeys.remove(alias+".crt");
    }

//    @Override
    public List<String> listPrivateKeys() throws IOException {
        List<String> files = privateKeys.list();
        ArrayList<String> privateKeyFiles = new ArrayList<String>();
        for(String file : files) {
            if( !file.endsWith(".crt") ) {
                privateKeyFiles.add(file);
            }
        }
        return privateKeyFiles;
    }

    // it says getPrivateKey because that's the CONTENT of the envelope, but the envelope itself is PASSWORD-PROTECTED.
    //  XXX TODO these classes need to be renamed to make it clearer probably -- the distinction between the envelope
    //  protection and the content that is being protected.  passwordkeyenvelope and rsakeyenvelope refer to the 
    // protection mechanism of the envelope, not to the contents, which could be either a secret key or an rsa key.
//    @Override
    public PasswordKeyEnvelope getPrivateKey(String alias) throws IOException {
        String content = privateKeys.getString(alias);
        PasswordKeyEnvelope envelope = PasswordKeyEnvelope.fromPem(content);
//        RsaKeyEnvelope envelope = RsaKeyEnvelope.fromPem(content);
        return envelope;
    }

    public X509Certificate getPrivateKeyCertificate(String alias) throws IOException {
        byte[] content = privateKeys.getBytes(alias+".crt");
        try {
            X509Certificate recipient = X509Util.decodeDerCertificate(content);
            return recipient;
        }
        catch(CertificateException e) {
            throw new IOException(e);
        }
    }

    // xxx todo ... need something like this, but it needs to return a "locked" credential (since we are not supply the
    // password here )   which is an object that contains the PasswordKeyEnvelope and the X509Certificate, and when
    // unlocked creates the credential
    public LockedRsaCredentialX509 getPrivateKeyCredential(String alias) throws IOException {
        return new LockedRsaCredentialX509(getPrivateKey(alias), getPrivateKeyCertificate(alias));
    }
    // xxx draft... just trying this out
    public static class LockedRsaCredentialX509 {
        private PasswordKeyEnvelope privateKeyEnvelope;
//        private RsaKeyEnvelope privateKeyEnvelope;
        private X509Certificate publicKeyCertificate;
        public LockedRsaCredentialX509(PasswordKeyEnvelope privateKeyEnvelope, X509Certificate publicKeyCertificate) {
            this.privateKeyEnvelope = privateKeyEnvelope;
            this.publicKeyCertificate = publicKeyCertificate;
        }
        public RsaCredentialX509 unlock(String password) throws CryptographyException {
            PasswordKeyEnvelopeRecipient recipient = new PasswordKeyEnvelopeRecipient(password);
//            RsaKeyEnvelopeReceipient recipient = new RsaKeyEnvelopeRecipient(password);
            Key privateKeyContent = recipient.unseal(privateKeyEnvelope);
            try {
                PrivateKey privateKey = RsaUtil.decodeDerPrivateKey(privateKeyContent.getEncoded());
                RsaCredentialX509 rsa = new RsaCredentialX509(privateKey,publicKeyCertificate);
                return rsa;
            }
            catch(CertificateEncodingException e) {
                throw new CryptographyException(e);
            }
        }
    }
    
    ///////////////////////////////////////////// Outbox of RSA-protected data encryption keys (for sharing with authorized recipients such as trusted servers)
    
//    @Override
    public void addRsaKeyEnvelope(String alias, RsaKeyEnvelope envelope) throws IOException {
        userKeys.add(alias, envelope.toPem());
    }

//    @Override
    public void removeRsaKeyEnvelope(String alias) throws IOException {
        userKeys.remove(alias);
    }

//    @Override
    public List<String> listRsaKeyEnvelopes() throws IOException {
        return userKeys.list();
    }

//    @Override
    public RsaKeyEnvelope getRsaKeyEnvelope(String alias) throws IOException {
        String content = userKeys.getString(alias);
        RsaKeyEnvelope envelope = RsaKeyEnvelope.fromPem(content);
        return envelope;
    }
    

    
}
