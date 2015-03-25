/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.client.jaxrs2;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.kms.user.UserFilterCriteria;
import com.intel.mtwilson.jaxrs2.client.JaxrsClient;
import com.intel.mtwilson.jaxrs2.client.JaxrsClientBuilder;
import java.util.HashMap;
import java.util.Properties;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.MediaType;
import com.intel.kms.user.User;
import com.intel.kms.user.UserCollection;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import java.security.PublicKey;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status.Family;

/**
 * To use password-based HTTP BASIC authorization with the user server, 
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
public class Users extends JaxrsClient {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Users.class);
    
    public Users(Properties properties) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(properties).build());
    }
    public Users(Configuration configuration) throws Exception {
        super(JaxrsClientBuilder.factory().configuration(configuration).build());
    }
    
    public User createUser(User user) {
        log.debug("createUser: {}", getTarget().getUri().toString());
        User created = getTarget().path("/v1/users").request().accept(MediaType.APPLICATION_JSON).post(Entity.json(user), User.class);
        return created;
    }
    
    public void deleteUser(User user) {
        deleteUser(user.getId().toString());
    }
    
    public void deleteUser(String userId) {
        log.debug("deleteUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", userId);
        getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).delete();
    }
    
    
    public User editUser(User user) {
        log.debug("editUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", user.getId());
        User edited = getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).put(Entity.json(user), User.class);
        return edited;
    }
    
    public boolean editTransferKey(String username, PublicKey transferKey) {
        log.debug("editTransferKey: {}", getTarget().getUri().toString());
        UserFilterCriteria searchUsersRequest = new UserFilterCriteria();
        searchUsersRequest.usernameEqualTo = username;
        UserCollection searchResults = searchUsers(searchUsersRequest);
        if( searchResults.getUsers().isEmpty() ) {
            log.debug("Username not found: {}", username);
            return false;
        }
        if( searchResults.getUsers().size() > 1 ) {
            log.debug("Multiple users found: {} x {}", username, searchResults.getUsers().size());
            return false;
        }
        User user = searchResults.getUsers().get(0);        
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", user.getId().toString());
        String transferKeyPem = RsaUtil.encodePemPublicKey(transferKey);
        Response response = getTarget().path("/v1/users/{id}/transfer-key").resolveTemplates(map).request().put(Entity.entity(transferKeyPem, CryptoMediaType.APPLICATION_X_PEM_FILE));
        log.debug("editTransferKey response status code {}", response.getStatus());
        if( response.getStatusInfo().getFamily().toString().equals(Family.SUCCESSFUL.toString())) {
            return true;
        }
        return false;
    }

    public UserCollection searchUsers(UserFilterCriteria searchUsersRequest) {
        log.debug("searchUsers: {}", getTarget().getUri().toString());
        UserCollection searchUsersResponse = getTargetPathWithQueryParams("/v1/users", searchUsersRequest).request().accept(MediaType.APPLICATION_JSON).get(UserCollection.class);
        return searchUsersResponse;
    }
    
    public User retrieveUser(String userId) {
        log.debug("retrieveUser: {}", getTarget().getUri().toString());
        HashMap<String,Object> map = new HashMap<>();
        map.put("id", userId);
        User retrieved = getTarget().path("/v1/users/{id}").resolveTemplates(map).request().accept(MediaType.APPLICATION_JSON).get(User.class);
        return retrieved;
    }
    
    
}
