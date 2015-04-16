package com.intel.kms.barbican.client.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

public class JsonUtil {

    public static String getString(Object object)
            throws BarbicanClientException {
        if (object == null) {
            throw new BarbicanClientException(
                    "Cannot convert NULL object to JSON");
        }
        ObjectMapper mapper = new ObjectMapper();
        String jsonString;
        try {
            jsonString = mapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            // TODO Auto-generated catch block
            throw new BarbicanClientException(e.getMessage());
        }
        return jsonString;
    }

    public static CreateKeyResponse getCreateKeyResponseObject(String jsonResponse,
            Class responseObject) throws BarbicanClientException {
        CreateKeyResponse response = null;
        Map<String, String> map = new HashMap<String, String>();
        ObjectMapper mapper = new ObjectMapper();
        try {
            KeyAttributes ka = new KeyAttributes();

            map = mapper.readValue(jsonResponse, new TypeReference<HashMap<String, String>>() {
            });
            ka.setTransferLink(new URL(map.get("secret_ref")));
            response = new CreateKeyResponse(ka);
        } catch (IOException ex) {
            Logger.getLogger(JsonUtil.class.getName()).log(Level.SEVERE, null, ex);
        }
        return response;
    }

    //TODO: implementation
    public static RegisterKeyResponse getRegisterKeyResponseObject(String jsonResponse,
            Class responseObject) throws BarbicanClientException {
        RegisterKeyResponse response = null;
        Map<String, String> map = new HashMap<String, String>();
        ObjectMapper mapper = new ObjectMapper();
        response = new RegisterKeyResponse();
        return response;
    }

    public static Map<String, String> convertJsonToMap(String str) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        HashMap<String, String> map = mapper.readValue(str, new TypeReference<HashMap<String, String>>() {});
        return map;
    }
}
