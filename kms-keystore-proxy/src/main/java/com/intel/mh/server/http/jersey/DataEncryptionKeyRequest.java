/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.server.http.jersey;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.dcsg.cpg.crypto.RsaCredentialX509;
import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelopeRecipient;
import com.intel.mtwilson.ApiClient;
import com.intel.mtwilson.KeystoreUtil;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.mtwilson.configuration.EncryptedConfigurationProvider;
import com.intel.mh.repository.ServerFileRepository;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.TrustAssertion;
import com.intel.mtwilson.api.ApiException;
import com.intel.mtwilson.api.ClientException;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.configuration.ConfigurationProvider;
import com.intel.mtwilson.saml.TrustAssertion.HostTrustAssertion;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Set;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
//import org.apache.commons.configuration.Configuration;
//import org.apache.commons.configuration.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * See also: http://docs.oracle.com/javaee/6/tutorial/doc/gilik.html
 *
 * @author jbuhacoff
 */
@Path("/data-encryption-key/request")
public class DataEncryptionKeyRequest {

    private Logger log = LoggerFactory.getLogger(getClass());
//    private MHServerConfig config = null;
    private Configuration secretConfig = null;
    private String password;

    /**
     * Example request:
     *
     * curl --verbose --insecure -X POST -H "Content-Type: text/plain" --data-binary
     *
     * @/etc/intel/cloudsecurity/cert/aikpubkey.pem https://10.254.57.240:8443/v1/data-encryption-key/request/testkey2
     *
     * Where the contents of /etc/intel/cloudsecurity/cert/aikpubkey.pem are: * -----BEGIN PUBLIC KEY-----
     * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7LLuu74Grs1FVlpZ3JE
     * nedg8zl3v2vV+Elui6PjTZxpez7veAOvBbQ2qaMbDe40fnrFRttnpLkhHZtYyJB0
     * c9P4XRYqOYsymNZpnbTDhZGLP3LsvvTWgZs/Sxwpthwv9+S/Tnxl+inLwWGCU98e
     * IN+hoeSoYQoKubR4b2teQBKhQd32ov7yUznOZj07I5IJFKLTEo8aJjLeupNcXWLa
     * 90CuievTv6f8Zt2CvSJJmM0FlGWgGu1ypZD/yu8DgfzcuAruQreu+aHsd2HD49nL
     * 8Dp+SkI0qI7gn8+zYpjojukRxazRY1KkCIX1MJ+wjVDjQ2QJBBgxIT8aOKcAfxT6 wwIDAQAB -----END PUBLIC KEY-----
     *
     * @param keyId
     * @param aik
     * @return
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}")
//    @Consumes(MediaType.APPLICATION_OCTET_STREAM)
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(MediaType.TEXT_PLAIN)
    public String requestDataEncryptionKey(@PathParam("keyId") String keyId, /*byte[] aik*/ String aik) {

        try {
            //bshah change start
            
//            PublicKey publicKey = RsaUtil.decodePemPublicKey(aik); // throws CryptographyException
//            Sha1Digest aikId = Sha1Digest.digestOf(publicKey.getEncoded());
            
            X509Certificate aikcert = X509Util.decodePemCertificate(aik);
            Sha1Digest aikId = Sha1Digest.digestOf(aikcert.getEncoded());
            
            //bshah change end
            log.debug("AIK SHA1: {}", aikId.toHexString());
        
            log.info("Received request for key:" + keyId+" by aik:" + aikId.toHexString());

            // load configuration 
            if (secretConfig == null) {
                ConfigurationProvider provider = ConfigurationFactory.getConfigurationProvider();  // the provider now gets the password from MTWILSON_PASSWORD or KMS_PASSWORD etc. automatically
//                EncryptedConfigurationProvider provider = new EncryptedConfigurationProvider(); // requires KMS_PASSWORD environment variable to be set, unless we use jaxrs injection to inject the Configuration and let the launcher provide it
                secretConfig = provider.load();
                password = secretConfig.get("kms.keystore.password");
                if( password == null ) {
                    // generate it and store it back to configuration;  should be done by a setup task instead so we can just throw an exception here
                    password = RandomUtil.randomBase64String(8);
                    secretConfig.set("kms.keystore.password", password);
                    provider.save(secretConfig);
                }
            }


            if (isHostTrustedByMtWilson(aikId)) {
                /*
                 // get the server cert
                 X509Certificate serverCert = api.getCurrentTrustCertificateByAik(new com.intel.mtwilson.model.Sha1Digest(aikId.toByteArray()));
                 if( serverCert == null ) {
                 throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).entity("Trust certificate not available for server identity").build());
                 }
                 log.debug("got certificate for trusted server,  loading dek");
                 */
                // for now we just encrypt it using the aik public key
                ServerFileRepository serverFileRepository = new ServerFileRepository(Folders.application()+File.separator+"repository");
//                ServerFileRepository serverFileRepository = config.getServerFileRepository();
                serverFileRepository.open();
                RsaKeyEnvelope keyEnvelope = serverFileRepository.getRsaKeyEnvelope(keyId);
                log.debug("got dek encrypted to {}", keyEnvelope.getEnvelopeKeyId());
                // load our own private key of the key management  server, in order to decrypt the dek we have stored
                RsaCredentialX509 rsa = serverFileRepository.getPrivateKeyCredential(keyEnvelope.getEnvelopeKeyId()).unlock(password);
                serverFileRepository.close();
                // decrypt the dek
                RsaKeyEnvelopeRecipient dekRecipient = new RsaKeyEnvelopeRecipient(rsa);
                Key dek = dekRecipient.unseal(keyEnvelope);

                log.info("Sending key:" + keyId+ " to aik:" + aikId.toHexString());

                // XXX TODO for now we are just providing the encryption key "PLAINTEXT" in order to complete the demonstration
                // BUT THE DESIGN REQUIRES IT TO BE ENCRYPTED USING THE PUBLIC KEY OF A SEALED PRIVATE KEY IN THE HOST'S TPM 
                // (EITHER ONE USED WITH ENFORCED ATTESTATION OR THE AIK IF THAT'S POSSIBLE)
                /*
                 // re-encrypt dek with host trusted certificate
                 RsaKeyEnvelopeFactory factory = new RsaKeyEnvelopeFactory(trustAssertion.getAikCertificate());
                 RsaKeyEnvelope envelope = factory.seal(dek);
                 envelope.setHeader("ContentKeyId", keyId); // add another header to the envelope to inform the server of the key id we have assigned to the key; so we can refer to it later
                 // return the envelope!
                 return envelope.toPem();
                 */
                return Base64.encodeBase64String(dek.getEncoded());
            } else {
                throw new WebApplicationException(Response.status(Response.Status.UNAUTHORIZED).entity("Host is not trusted").build());
            }
        } catch (CryptographyException e) {
            throw new WebApplicationException(Response.status(Response.Status.BAD_REQUEST).entity("Request data must be RSA public key").build());
        } catch (Exception e) {
            log.error("server error", e);
            throw new WebApplicationException(Response.status(Response.Status.INTERNAL_SERVER_ERROR).build());
        }
    }

    private boolean isHostTrustedByMtWilson(Sha1Digest aikId) throws IOException, ClientException, ApiException, SignatureException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateEncodingException, KeyManagementException, CryptographyException {
        // check that the aik we received is a valid public key
//            PublicKey publicKey = RsaUtil.decodeDerPublicKey(aik);
        // get trust status for that host from mt wilson
        ServerFileRepository repository = new ServerFileRepository(Folders.application()+File.separator+"repository");
        File mtwilsonKeystore = new File(repository.getMtWilsonClientKeystorePath());
        String mtwilsonUsername = secretConfig.get("mtwilson.api.username");
        String mtwilsonPassword = secretConfig.get("mtwilson.api.password");
        String mtwilsonUrl = secretConfig.get("mtwilson.api.url");
        log.debug("MtWilson URL: {}", mtwilsonUrl);
        log.debug("MtWilson Username: {}", mtwilsonUsername);
        log.info("Requesting trust assertion for aik:" + aikId.toHexString());
        ApiClient api = KeystoreUtil.clientForUserInResource(new FileResource(mtwilsonKeystore), mtwilsonUsername, mtwilsonPassword, new URL(mtwilsonUrl)); // throws ClientException, KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateEncodingException, FileNotFoundException, KeyManagementException
//            HostTrustResponse hostTrustResponse = api.getHostTrustByAik(new com.intel.mtwilson.model.Sha1Digest(aikId.toByteArray()));  // convert from cpg-crypto Sha1Digest to mtwilson-crypto Sha1Digest, needed until Mt Wilson is updated to use cpg-crypto
//            log.debug("trust status for {}", hostTrustResponse.hostname.toString());
//            log.debug("bios: {}", hostTrustResponse.trust.bios);
//            log.debug("vmm: {}", hostTrustResponse.trust.vmm);
        String saml = api.getSamlForHostByAik(new com.intel.mtwilson.model.Sha1Digest(aikId.toByteArray()), true); // throws ApiException, SignatureException ; true means we want to force a fresh attestation; set to false if it's ok to get a cached rseponse
        log.info("Received trust assertion for aik:" + aikId.toHexString());
        TrustAssertion trustAssertion = api.verifyTrustAssertion(saml);
        log.debug("trust status for {}", trustAssertion.getHosts());
        log.debug("trust assertion valid? {}", trustAssertion.isValid());
        String hostname = aikId.toHexString();
//        HostTrustAssertion hostTrustAssertion = trustAssertion.getTrustAssertion(hostname);
       Set <String> set =  trustAssertion.getHosts();
        for (String host : set){
            hostname = host;
            break;
        }
        log.debug("hostname"+hostname);
        HostTrustAssertion hostTrustAssertion = trustAssertion.getTrustAssertion(hostname);
         
        log.debug("trust assertion for host {}", hostTrustAssertion);
        log.debug("host is trusted? {}", hostTrustAssertion.isHostTrusted());
        if (hostTrustAssertion.isHostTrusted()) {
            log.info("Host is trusted with aik:" + aikId.toHexString());
            return true;
        }
        return false;
    }
}
