/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.RegisterKeyRequest;

/**
 *
 * @author soakx
 */
public class BarbicanDTO {

    public static String getBarbicanJsonForCreateKey(CreateKeyRequest request) throws JsonProcessingException {
        Root root = new Root();
        Secret secret = new Secret();
        secret.algorithm = request.getAlgorithm();
        secret.bit_length = request.getKeyLength();
        secret.mode = request.getMode();
        secret.name = "KMS_BARBICAN_KEY";
        secret.payload_content_type = "application/octet-stream";
        root.secret = secret;
        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(root);
    }

    public static String getBarbicanJsonForRegisterKey(RegisterKeyRequest request) throws JsonProcessingException {
        Root root = new Root();
        Secret secret = new Secret();
        secret.algorithm = request.getDescriptor().getEncryption().getAlgorithm();
        secret.bit_length = request.getDescriptor().getContent().getKeyLength();
        secret.mode = request.getDescriptor().getEncryption().getMode();
        secret.name = "KMS_BARBICAN_KEY";
        secret.payload_content_type = "application/octet-stream";
        secret.payload_content_encoding = "base64";
        secret.secret_type = "symmetric";
        secret.payload = new String(request.getKey());
        root.secret = secret;

        ObjectMapper mapper = new ObjectMapper();
        return mapper.writeValueAsString(root);
    }

    @JsonInclude(Include.NON_NULL)
    private static class Root {

        Secret secret;

        public Root() {
        }

        public Secret getSecret() {
            return secret;
        }

        public void setSecret(Secret secret) {
            this.secret = secret;
        }

    }

    @JsonInclude(Include.NON_NULL)
    private static class Secret {

        String status;
        String secret_type;
        String updated;
        String name;
        String algorithm;
        String mode;
        int bit_length;
        String payload;
        String payload_content_type;
        String payload_content_encoding;

        public Secret() {
        }

        public String getPayload() {
            return payload;
        }

        public void setPayload(String payload) {
            this.payload = payload;
        }

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public String getSecret_type() {
            return secret_type;
        }

        public void setSecret_type(String secret_type) {
            this.secret_type = secret_type;
        }

        public String getUpdated() {
            return updated;
        }

        public void setUpdated(String updated) {
            this.updated = updated;
        }

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getMode() {
            return mode;
        }

        public void setMode(String mode) {
            this.mode = mode;
        }

        public int getBit_length() {
            return bit_length;
        }

        public void setBit_length(int bit_length) {
            this.bit_length = bit_length;
        }

        public String getPayload_content_type() {
            return payload_content_type;
        }

        public void setPayload_content_type(String payload_content_type) {
            this.payload_content_type = payload_content_type;
        }

        public String getPayload_content_encoding() {
            return payload_content_encoding;
        }

        public void setPayload_content_encoding(String payload_content_encoding) {
            this.payload_content_encoding = payload_content_encoding;
        }

    }

}
