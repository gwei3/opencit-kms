/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.ws.v2;

import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.api.util.PemUtils;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;
import com.intel.mtwilson.jaxrs2.NoLinks;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.jaxrs2.server.resource.AbstractJsonapiResource;
import com.intel.mtwilson.launcher.ws.ext.V2;
import com.intel.mtwilson.shiro.Username;
import java.util.Collection;
import java.util.Iterator;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class Keys extends AbstractJsonapiResource<Key, KeyCollection, KeyFilterCriteria, NoLinks<Key>, KeyLocator> {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Keys.class);

    private KeyRepository repository;

    public Keys() {
        repository = new KeyRepository();
    }

    @Override
    protected KeyCollection createEmptyCollection() {
        return new KeyCollection();
    }

    @Override
    protected KeyRepository getRepository() {
        return repository;
    }
    
    /**
     * Register an existing key in PEM format.
     *
     * Example request:
     * <pre>
     * POST /keys
     * Content-Type: application/x-pem-file
     *
     * -----BEGIN SECRET KEY-----
     * EnvelopeKeyId: sha256-of-public-key-in-hex
     * EnvelopeAlgorithm: RSA
     * ContentAlgorithm: AES
     * 
     * (base64 encoded data here, the AES key encrypted by the RSA key)
     * -----END SECRET KEY-----
     * </pre>
     *
     * Example response:
     *
     *
     * @param registerKeyRequest
     * @return
     */
    @POST
    @Consumes(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @Produces(MediaType.APPLICATION_JSON)
    public KeyCollection registerKeyPEM(String pemText) {
        log.debug("registerKeyPEM");
//        Pem pem = Pem.valueOf(pemText);
        return getRepository().registerFromPEM(pemText);
    }
    
    
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @RequiresPermissions("keys:transfer")
    public TransferKeyResponse transferKey(@PathParam("keyId") String keyId /*, TransferKeyRequest keyRequest*/) {
        log.debug("transferKey");
        TransferKeyRequest keyRequest = new TransferKeyRequest();
        keyRequest.setKeyId(keyId);
        keyRequest.setUsername(getLoginUsername());
        return KeyRepository.getKeyManager().transferKey(keyRequest);
    }
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @RequiresPermissions("keys:transfer")
    public String transferKeyPEM(@PathParam("keyId") String keyId /*, TransferKeyRequest keyRequest*/) {
        log.debug("transferKeyPEM");
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest();
        transferKeyRequest.setKeyId(keyId);
        transferKeyRequest.setUsername(getLoginUsername());
        TransferKeyResponse transferKeyResponse = KeyRepository.getKeyManager().transferKey(transferKeyRequest);
        Pem pem = PemUtils.fromTransferKeyResponse(transferKeyResponse.getKey(), transferKeyResponse.getDescriptor());
        return pem.toString();
    }
    
    protected String getLoginUsername() {
        Subject subject = SecurityUtils.getSubject();
        log.debug("Got subject: {}", subject);
        PrincipalCollection principals = subject.getPrincipals();
        log.debug("Got principal collection: {}", principals.asList());
        Collection<Username> usernames = principals.byType(Username.class);
        log.debug("Got usernames: {}", usernames);
        Iterator<Username> it = usernames.iterator();
        if( it.hasNext() ) {
            String username = it.next().getUsername();
            log.debug("Got username: {}", username);
            return username;
        }
        return null;
    }
    
}
