/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import com.intel.kms.ws.v2.api.Key;
import com.intel.kms.ws.v2.api.KeyCollection;
import com.intel.kms.ws.v2.api.KeyFilterCriteria;

/**
 * To use password-based HTTP BASIC authorization with the key server, 
 * the client must be initialized with the following properties:
 * endpoint.url, login.basic.username, login.basic.password, and any valid TLS
 * policy. The example below uses the Properties format, a sample URL, and
 * a sample TLS certificate SHA-1 fingerprint:
 * 
 * <pre>
endpoint.url=https://kms.example.com
tls.policy.certificate.sha1=8d657a6b344a91d9744c3e9ee73071bd39979adf
login.basic.username=client-username
login.basic.password=client-password
 * </pre>
 * 
 * @author jbuhacoff
 */
public class Keys extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Keys.class);
    
    public Keys(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public Keys(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    public Key createKey(CreateKeyRequest createKeyRequest) {
        log.debug("createKey: {}", getTarget().getUri().toString());
        Key createKeyResponse = getTarget().path("/v1/keys").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(createKeyRequest), Key.class);
        return createKeyResponse;
    }
    
    public KeyCollection registerKey(RegisterKeyRequest registerKeyRequest) {
        log.debug("registerKey: {}", getTarget().getUri().toString());
        KeyCollection registerKeyResponse = getTarget().path("/v1/keys").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(registerKeyRequest), KeyCollection.class);
        return registerKeyResponse;
    }
    
    public DeleteKeyResponse deleteKey(DeleteKeyRequest deleteKeyRequest) {
        log.debug("deleteKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", deleteKeyRequest.getKeyId());
        DeleteKeyResponse deleteKeyResponse = getTarget().path("/v1/keys/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete(DeleteKeyResponse.class);
        return deleteKeyResponse;
    }
    
    public void deleteKey(String keyId) {
        DeleteKeyRequest deleteKeyRequest = new DeleteKeyRequest(keyId);
        DeleteKeyResponse deleteKeyResponse = deleteKey(deleteKeyRequest);
        if( deleteKeyResponse != null && !deleteKeyResponse.getFaults().isEmpty() ) {
            // log errors and throw exception
            for(Fault fault : deleteKeyResponse.getFaults() ) {
                log.error("Cannot delete key {}: {}", keyId, fault.toString());
            }
            throw new IllegalArgumentException("Cannot delete key");
        }
    }
    
    
    public TransferKeyResponse transferKey(TransferKeyRequest transferKeyRequest) {
        log.debug("transferKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", transferKeyRequest.getKeyId());
        TransferKeyResponse transferKeyResponse = getTarget().path("/v1/keys/{id}/transfer").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).post(Entity.json(transferKeyRequest), TransferKeyResponse.class);
        return transferKeyResponse;
    }
    public String transferKey(String keyId) {
        log.debug("transferKey: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", keyId);
        // note we are sending an empty post body because this transfer request requires only key id (from url) and username (from login) which are already available to server without any message body
        String transferKeyResponse = getTarget().path("/v1/keys/{id}/transfer").resolveTemplates(map).request().accept(CryptoMediaType.APPLICATION_X_PEM_FILE).post(Entity.text(""), String.class);
        return transferKeyResponse;
    }

    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest getKeyAttributesRequest) {
        log.debug("searchKeyAttributes: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", getKeyAttributesRequest.getKeyId());
        GetKeyAttributesResponse getKeyAttributesResponse = getTarget().path("/v1/keys/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(GetKeyAttributesResponse.class);
        return getKeyAttributesResponse;
    }
    
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        log.debug("searchKeyAttributes: {}", getTarget().getUri().toString());
        SearchKeyAttributesResponse searchKeyAttributesResponse = getTargetPathWithQueryParams("/v1/keys", searchKeyAttributesRequest).request().accept(MediaType.APPLICATION_JSON).get(SearchKeyAttributesResponse.class);
        return searchKeyAttributesResponse;
    }
    
    
    
}
