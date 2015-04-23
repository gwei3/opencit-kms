/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.httpclient.rs;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.barbican.api.DeleteSecretRequest;
import com.intel.kms.barbican.api.DeleteSecretResponse;
import com.intel.kms.barbican.api.RegisterSecretRequest;
import com.intel.kms.barbican.api.RegisterSecretResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.util.HashMap;
import java.util.Map;
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;

/**
 *
 * @author GS-0681
 */
public class Secrets extends BarbicanOperation {

    public Secrets(Configuration configuration) throws BarbicanClientException {
        super(configuration);
    }

    public TransferSecretResponse transferSecret(TransferSecretRequest transferSecretRequest) {
        LOG.debug("transferSecret: {}", getTarget().getUri().toString());
        Map<String, Object> map = new HashMap<>();
        map.put("id", transferSecretRequest.id);
        TransferSecretResponse transferSecretResponse = getTarget().path("/v1/secrets/{id}").
                resolveTemplates(map).
                request().
                header("X-Project-Id", transferSecretRequest.projectId).
                accept(transferSecretRequest.accept).
                get(TransferSecretResponse.class);
        return transferSecretResponse;

    }

    public RegisterSecretResponse registerSecret(RegisterSecretRequest registerSecretRequest) {
        RegisterSecretResponse registerSecretResponse;
        LOG.debug("registerSecretResponse: {}", getTarget().getUri().toString());
        registerSecretResponse = getTarget().path("/v1/secrets").request().
                header("X-Project-Id", registerSecretRequest.projectId).
                header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON).
                accept(MediaType.APPLICATION_JSON).
                post(Entity.json(registerSecretRequest), RegisterSecretResponse.class);
        return registerSecretResponse;
    }

    public DeleteSecretResponse deleteSecret(DeleteSecretRequest deleteSecretRequest) {
        DeleteSecretResponse deleteSecretResponse;
        LOG.debug("deleteSecret: {}", getTarget().getUri().toString());
        Map<String, Object> map = new HashMap<>();
        map.put("id", deleteSecretRequest.id);
        deleteSecretResponse = getTarget().path("/v1/secrets/{id}").resolveTemplates(map).request().
                header("X-Project-Id", deleteSecretRequest.projectId).
                accept(MediaType.APPLICATION_JSON).
                delete(DeleteSecretResponse.class);
        return deleteSecretResponse;
    }
}
