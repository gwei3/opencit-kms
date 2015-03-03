/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.console.cmd;

import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.console.input.Input;
import com.intel.dcsg.cpg.crypto.Md5Digest;
import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelopeFactory;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.x509.X509Builder;
import com.intel.mh.repository.ServerFileRepository;
import com.intel.mtwilson.Folders;
import java.io.File;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
/**
 * 
 * How to run this command to create a key management certificate:
 * 
 * java -jar client-0.1-SNAPSHOT-with-dependencies.jar CreateKeyManagementCertificate
 * 
 * The public key output is a DER-encoded X509 certificate.
 * 
 * Sample private key output:
-----BEGIN SECRET KEY-----
EnvelopeAlgorithm: PBEWithMD5AndDES/CBC/PKCS5Padding
EnvelopeKeyId: 67cexVt7hzI=:puZAket7/v+brC1e0uZQclU8Jhq9CQxNzK6IOgenDgQ=
ContentAlgorithm: RSA

wmWBSwQLXCuoyjI2/AS/ldc7H/pS2szNNXVnptVUhY2iKLmW12mHngTPo6qeffU9xqyqZyhX7+TK
LeeoUZ8OmLj/2Murf5suHzDAAY9NM9AEr8Y7bF/ySUgFICy6CIHHbGdTHhWPlx+daOoAF0v//iXd
3L59FaHRLjzx24lSyJpYxG//XAhUwQ0Ntvj8BLegDly3hEi+uxFI8bJibPDt7B/rJVfMo1yVom8F
EK2j0UmYy9dqCy/KtQ3uC2i0/X2NkMNcNp75Aw2cErVK2aCbMWw5riEXaZ6XUhxbXBCwEVdcXhQw
eQ2Nkamkvdm4Fp11HUsgwzWv9hcXDZ+fLaSkZr6JsM/R0MrGogeOJP6+xRXhOIb+F/2AHoxGyGqh
ySP13n9aoNnujnGfa6PcgVtlj9ZZDwd+QLxPiQ+QCz/ydkfH/3EXmW/rc0d6i3qfDHGcjFMl49wA
SOpgPre+skpDcFvX8tHW+Eknhw3bUKGGcOlOdl/xL1YtHjBDKOfkjG5Sn/KORPDuB8uztpIMeSNa
p1HfEu3rh/EZDI2tdfnODB25d9dB254CD41df9TBXYOqvhSaQl5X7dxGIZgYvwVh7FQATQCrPS3I
sG1Q2jxsgUUhCjXJkWH3gaAHIajEaWCaiLFSzw43jfDZA3QscKyheWly1p8OXDW0cEPAw0c4rJhk
6eYjO2c/biDu8irHpNQYw2q48Fem+6BtNnoU9JePlCXuOYmfRkefR13OVJpSRGNjatoDXdCPNb6H
o2ZkC5ezZnSyCNn3F8iLJd6c3LqTuw6DNxWFybBNVVUC/5PgNBAkvHHCKrMnhXYduCSmQ4Sw07Se
JcjJmVrNcR3i2rrU3bTCBxS0ZE+9CSTDL7uAx7DwTp1DH8UpqsrP3q8+E1qo3QXnY3tK3+RoYKK4
nf/eFh6kKRGcFoLVXrOPHM9NOlrNjDjOsBKHikjdyidVCRHiGeI9t4nlSZ+hwBuztdlqsFJstUkd
/hmNhjLBMZpduZbF3KFwNx5+CEVGaOVS7wUwgMOic6GM08mSVdoHKYMArfycY26GGqr7IgKp5+/7
Zw6STQozqTtVpQRMUI3RlALop1WsdHdRM9qseptyThWnzM3t/uRIrKz9M+g147E1ZxGmJO7nfNHz
TLcyHzPeEvbc+HuicczOOlHgL13TvCzSQxLdxc1upIC+RH0L26g643ozrFO8IGUPpa9FzoEoRn0U
tWWq35lqi7/Ib9mjv8pNmkvDg6jemPNi45TK2klXhTYBQhWr+mhzaNOrRLQNc48mjn6p05LlLOJ9
+aWW+JjTxy+Qy4VC3We3GCTkdo1nA8B61WMnHy6Vch1y+3W1F+QeMN1I1+T4QZyc/QhEOX6C2wrO
SAYxCn6CqQErd/MYd30YCkF05u6wWaUtU6KXGV5Sbobg+RIZ1HDaHdgGERUDpCEKwmbcDyGEdK9x
e0N9TILxnwfLxYHmaJxDYLSbGa7UfXxyDliVl0/b7p3J0Mg7PD2u6kZp4LUjkzTo4auqarUIvzY5
v9nqH5U571omaSh+Cy2o2culNiOpvE/hfLA2eH7oMvouhEGJ+4uogz62pTZi7SGIivVls/Eards7
keb/pQ6+Bd2zAqpPKcYHuHv9xFaGPuQgnQmY
-----END SECRET KEY-----
 * 
 * @author jbuhacoff
 */
public class CreateKeyManagementCertificate extends InteractiveCommand {

    @Override
    public void execute(String[] args) throws Exception {
        ServerFileRepository repository = new ServerFileRepository(Folders.application()+File.separator+"repository");
        repository.open();
        
//        if( args.length < 1) { throw new IllegalArgumentException("Usage: CreateKeyManagementCertificate"); }
//        String alias = args[0];

        String password;
        if( this.options != null && options.containsKey("env-password") ) {
            password = options.getString("env-password");
        }
        else {
            password = Input.getConfirmedPasswordWithPrompt("You must protect the Private Key with a password."); // always returns value or expression
        }

        KeyPair keypair = RsaUtil.generateRsaKeyPair(2048);
        X509Certificate certificate = X509Builder.factory().selfSigned("CN=key mgmt svc", keypair).keyUsageKeyEncipherment().build(); // XXX TODO  allow customizing the distinguished name of the cert using command line options
        
        // create the password-protected private key envelope
        PasswordKeyEnvelopeFactory factory = new PasswordKeyEnvelopeFactory(password);
        PasswordKeyEnvelope envelope = factory.seal(keypair.getPrivate());
        
        // write out the password-protected private key and corresponding x509 certificate
        String alias = Md5Digest.digestOf(certificate.getEncoded()).toString();
        repository.addPrivateKey(alias, envelope, certificate);
        
        System.out.println(String.format("Created private key: %s", alias));
    }
    
}
