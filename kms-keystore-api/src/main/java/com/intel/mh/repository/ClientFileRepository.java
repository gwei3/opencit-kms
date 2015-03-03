/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import com.intel.dcsg.cpg.io.file.FileRepository;
import java.io.File;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public class ClientFileRepository {
    private final String path;
    private FileRepository deks; // password-protected data encryption keys
//    private FileRepository recipients; // x509 certificates of authorized recipients of data encryption keys
//    private KeystoreCertificateRepository recipients; // password-protected x509 certificates of authorized recipients of data encryption keys
    private FileRepository outbox; // rsa-protected data encryption keys that are ready to share with recipients
    
    /**
     * 
     * @param path for example System.getProperty("user.home") + File.separator + ".mystery-hill"
     */
    public ClientFileRepository(String path) {
        this.path = path;
    }
    
    /**
     * MHClient stores password-encrypted DEK's here.
     * MHKeyMgmtSvc stores RSA-encrypted DEK's here (received from MHClient)
     * @return 
     */
    public String getDekPath() { return path + File.separator + "dek"; }
//    public String getRecipientPath() { return path + File.separator + "dek-recipient"; }
    public String getOutboxPath() { return path + File.separator + "dek-outbox"; }

    
    /**
     * Post-condition:  the member variables dekFolder, recipientFolder, privateKeyFolder point to existing directories
     */
    public void open() {
        // create all necessary directories
        deks = new FileRepository(getDekPath());
        deks.open();
//        recipients = new FileRepository(getRecipientPath());
//        recipients.open();
        outbox = new FileRepository(getOutboxPath());
        outbox.open();
    }
    
    public void close() {
        deks.close();
//        recipients.close();
        outbox.close();
    }
    
    ///////////////////////////////////////////// Password-protected data encryption keys
    
//    @Override
    public void addPasswordKeyEnvelope(String alias, PasswordKeyEnvelope envelope) throws IOException {
        deks.add(alias, envelope.toPem());
    }

//    @Override
    public void removePasswordKeyEnvelope(String alias) throws IOException {
        deks.remove(alias);
    }

//    @Override
    public List<String> listPasswordKeyEnvelopes() throws IOException {
        return deks.list();
    }

//    @Override
    public PasswordKeyEnvelope getPasswordKeyEnvelope(String alias) throws IOException {
        String content = deks.getString(alias);
        PasswordKeyEnvelope envelope = PasswordKeyEnvelope.fromPem(content);
        return envelope;
    }
    
    ///////////////////////////////////////////// Recipients of wrapped data encryption keys

    /*
//    @Override
    public void addRecipient(String alias, X509Certificate recipient) throws IOException {
        try {
            recipients.add(alias, recipient.getEncoded());
        }
        catch(CertificateEncodingException e) {
            throw new IOException(e);
        }
    }

//    @Override
    public void removeRecipient(String alias) throws IOException {
        recipients.remove(alias);
    }

//    @Override
    public List<String> listRecipients() throws IOException {
        return recipients.list();
    }

//    @Override
    public X509Certificate getRecipient(String alias) throws IOException {
        byte[] content = recipients.getBytes(alias);
        try {
            X509Certificate recipient = X509Util.decodeDerCertificate(content);
            return recipient;
        }
        catch(CertificateException e) {
            throw new IOException(e);
        }
    }
    */

    ///////////////////////////////////////////// Outbox of RSA-protected data encryption keys (for sharing with dek recipients such as key mgmt svc)
    
//    @Override
    public void addRsaKeyEnvelope(String alias, RsaKeyEnvelope envelope) throws IOException {
        outbox.add(alias, envelope.toPem());
    }

//    @Override
    public void removeRsaKeyEnvelope(String alias) throws IOException {
        outbox.remove(alias);
    }

//    @Override
    public List<String> listRsaKeyEnvelopes() throws IOException {
        return outbox.list();
    }

//    @Override
    public RsaKeyEnvelope getRsaKeyEnvelope(String alias) throws IOException {
        String content = outbox.getString(alias);
        RsaKeyEnvelope envelope = RsaKeyEnvelope.fromPem(content);
        return envelope;
    }
    

    
}
