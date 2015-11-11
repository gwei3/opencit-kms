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
import com.intel.mtwilson.shiro.ShiroUtil;
import com.intel.mtwilson.shiro.Username;
import com.intel.mtwilson.util.validation.faults.Thrown;
import com.thoughtworks.xstream.XStream;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import org.apache.commons.codec.binary.Base64;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
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
    protected static final String AUTHORIZATION_HEADER = "Authorization";
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
    public TransferKeyResponse transferKey(@PathParam("keyId") String keyId, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse /*, TransferKeyRequest keyRequest*/) {
        log.debug("transferKey");
        TransferKeyRequest keyRequest = new TransferKeyRequest();
        keyRequest.setKeyId(keyId);
        keyRequest.setUsername(ShiroUtil.subjectUsername());
        try {
        return getRepository().getKeyManager().transferKey(keyRequest);
        }
        catch(Exception e) {
            TransferKeyResponse response = new TransferKeyResponse();
            response.getFaults().add(new Thrown(e));
            return response;
        }
    }

    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(MediaType.TEXT_PLAIN)
    @Produces(CryptoMediaType.APPLICATION_X_PEM_FILE)
    @RequiresPermissions("keys:transfer")
    public String transferKeyPEM(@PathParam("keyId") String keyId, @Context HttpServletRequest httpServletRequest, @Context HttpServletResponse httpServletResponse /*, TransferKeyRequest keyRequest*/) throws IOException {
        log.debug("transferKeyPEM");
        TransferKeyRequest transferKeyRequest = new TransferKeyRequest();
        transferKeyRequest.setKeyId(keyId);
        transferKeyRequest.setUsername(ShiroUtil.subjectUsername());
        TransferKeyResponse transferKeyResponse = getRepository().getKeyManager().transferKey(transferKeyRequest);
        Pem pem = PemUtils.fromTransferKeyResponse(transferKeyResponse.getKey(), transferKeyResponse.getDescriptor());
        return pem.toString();
    }


}
