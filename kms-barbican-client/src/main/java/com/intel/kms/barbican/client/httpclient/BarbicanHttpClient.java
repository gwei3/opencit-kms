package com.intel.kms.barbican.client.httpclient;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.client.dto.BarbicanDTO;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.util.Map;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HostConfiguration;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.DeleteMethod;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.PutMethod;
import org.apache.commons.httpclient.methods.RequestEntity;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 *
 * @author soakx
 */
public class BarbicanHttpClient {

    private static BarbicanHttpClient barbicanHttpClient = null;
    private HttpClient httpClient;

    public void setHttpClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    private static final String BARBICAN_SERVER_HOST = "localhost";
    private static final int BARBICAN_SERVER_PORT = 9311;
    private static final String BARBICAN_POST_SECRET = "/v1/secrets";
    private static final String BARBICAN_CREATE_SECRET = "/v1/orders";
    private static final String REQUEST_HEADER_CONTENT_TYPE = "content-type";
    private static final String REQUEST_HEADER_ACCEPT = "content-type";
    private static final String REQUEST_HEADER_PROJECT_ID = "X-Project-Id";
    private static final String REQUEST_HEADER_CONTENT_TYPE_APP_JSON = "application/json";
    private static final String REQUEST_HEADER_CONTENT_TYPE_APP_OCTET_STREAM = "application/octet-stream";

    private BarbicanHttpClient() {
        httpClient = new HttpClient();
        HostConfiguration configuration = new HostConfiguration();
        configuration.setHost(BARBICAN_SERVER_HOST, BARBICAN_SERVER_PORT);
        httpClient.setHostConfiguration(configuration);
    }

    public static BarbicanHttpClient getBarbicanHttpClient() {
        if (barbicanHttpClient == null) {
            barbicanHttpClient = new BarbicanHttpClient();
        }
        return barbicanHttpClient;
    }

    /**
     * Barbican can generate secrets via the orders resource Create an order
     * (which will then generate a secret) as follows:
     *
     * curl -X POST -H 'content-type:application/json' -H 'X-Project-Id: 12345'
     * -d '{ "secret": {"name": "secretname", "algorithm": "aes", "bit_length":
     * 256, "mode": "cbc", "payload_content_type": "application/octet-stream"}}'
     * http://localhost:9311/v1/orders
     *
     * You should see a response like the following: {"order_ref":
     * "http://localhost:9311/v1/orders/62d57f53-ecfe-4ae4-87bd-fab2f24e29bc"}
     *
     *
     * Once the request is made, the barbican would respond with 202 OK and a
     * link to the order : "order_ref":
     * "http://localhost:9311/v1/orders/30b3758a-7b8e-4f2c-b9f0-f590c6f8cc6d"
     *
     * Make another call to barbican to get the order details
     *
     * The response would contain URL to the secret: {"status": "ACTIVE",
     * "secret_ref":
     * "http://localhost:9311/v1/secrets/2df8d196-76b6-4f89-a6d2-c9e764900791",
     * "updated": "2013-11-04T16:39:13.593962", "name": "secretname",
     * "algorithm": "aes", "created": "2013-11-04T16:39:13.593956",
     * "content_types": {"default": "application/octet-stream"}, "mode": "cbc",
     * "bit_length": 256, "expiration": null}
     *
     * @param request
     * @return CreateKeyResponse with the URL to the secret
     * @throws BarbicanClientException
     */
    public CreateKeyResponse createSecret(CreateKeyRequest request)
            throws BarbicanClientException {
        CreateKeyResponse response = null;
        PostMethod postMethod = new PostMethod(BARBICAN_CREATE_SECRET);

        //Set the header
        Header headerContentType = new Header(REQUEST_HEADER_CONTENT_TYPE, REQUEST_HEADER_CONTENT_TYPE_APP_JSON);
        Header headerProjectId = new Header(REQUEST_HEADER_PROJECT_ID, "123456");
        postMethod.addRequestHeader(headerContentType);
        postMethod.addRequestHeader(headerProjectId);

        //build the JSON representation of the data to be sent to Barbican
        String body = null;
        try {
            body = BarbicanDTO.getBarbicanJsonForCreateKey(request);
        } catch (JsonProcessingException ex) {
            throw new BarbicanClientException("Unable to contruct JSON for CREATE request", ex);
        }

        //Construct an entity
        RequestEntity entity;
        try {
            entity = new StringRequestEntity(body, "application/json", "UTF-8");
        } catch (UnsupportedEncodingException e1) {
            throw new BarbicanClientException("Error constructing request body");
        }

        // Set the JSON string of the CreateSecretRequest in the POST body
        postMethod.setRequestEntity(entity);

        try {
            // make the POST request to start the key create process
            httpClient.executeMethod(postMethod);
            int statusCode = postMethod.getStatusCode();
            if (statusCode != 202) {
                throw new BarbicanClientException("Thhe key generation process was not started");
            }
            response = new CreateKeyResponse();
            KeyAttributes keyAttributes = new KeyAttributes();

            String responseBodyAsString = postMethod.getResponseBodyAsString();

            //Extract the order_ref
            String orderRef = JsonUtil.convertJsonToMap(responseBodyAsString).get("order_ref");

            //Make a GET request to get the order details            
            GetMethod getMethod = new GetMethod(orderRef);
            httpClient.executeMethod(getMethod);
            responseBodyAsString = getMethod.getResponseBodyAsString();
            //Extract the secret_ref
            Map<String, String> map = JsonUtil.convertJsonToMap(responseBodyAsString);
            String secretRef = map.get("secret_ref");
            KeyAttributes attribute = new KeyAttributes();
            attribute.setTransferLink(new URL(secretRef));
            attribute.setAlgorithm(map.get("algorithm"));
            attribute.setKeyId(secretRef.substring(secretRef.lastIndexOf("/") + 1));
            attribute.setKeyLength(Integer.getInteger(map.get("bit_length")));
            response.getData().add(attribute);
        } catch (HttpException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "HttpException");
            throw barbicanClientException;
        } catch (IOException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "Error communicating with the server");
            throw barbicanClientException;
        }
        return response;
    }

    /**
     * sample curl request to get the secret curl -H
     * 'Accept:application/octet-stream' -H 'X-Project-Id: 12345'
     * http://localhost:9311/v1/secrets/2df8d196-76b6-4f89-a6d2-c9e764900791
     *
     * @param request
     * @return TransferKeyResponse with the key populated
     */
    public TransferKeyResponse retrieveSecret(TransferKeyRequest request) throws BarbicanClientException {
        TransferKeyResponse response = null;
        StringBuilder url = new StringBuilder(BARBICAN_POST_SECRET);
        url.append("/");
        url.append(request.getKeyId());
        GetMethod getMethod = new GetMethod(url.toString());

        //Set the header
        Header headerContentType = new Header(REQUEST_HEADER_ACCEPT, REQUEST_HEADER_CONTENT_TYPE_APP_OCTET_STREAM);
        Header headerProjectId = new Header(REQUEST_HEADER_PROJECT_ID, "123456");
        getMethod.addRequestHeader(headerContentType);
        getMethod.addRequestHeader(headerProjectId);

        // make the GET request
        try {
            httpClient.executeMethod(getMethod);
            byte[] key = getMethod.getResponseBody();
            response = new TransferKeyResponse();
            response.setKey(key);
        } catch (HttpException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "HttpException");
            throw barbicanClientException;
        } catch (IOException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "Error communicating with the server");
            throw barbicanClientException;
        }
        return response;
    }

    /**
     *
     * Header: content-type=application/json X-Project-Id: {project_id}
     *
     * {
     * "name": "AES key", "expiration": "2014-02-28T19:14:44.180394",
     * "algorithm": "aes", "bit_length": 256, "mode": "cbc", "payload":
     * "gF6+lLoF3ohA9aPRpt+6bQ==", "payload_content_type":
     * "application/octet-stream", "payload_content_encoding": "base64",
     * "secret_type": "opaque" }
     *
     * On successful retrieval, barbican returns the following reponse {
     * "secret_ref":
     * "http://localhost:9311/v1/secrets/a8957047-16c6-4b05-ac57-8621edd0e9ee" }
     *
     *
     * @param request
     * @return
     * @throws BarbicanClientException
     */
    public RegisterKeyResponse registerSecret(RegisterKeyRequest request) throws BarbicanClientException {
        RegisterKeyResponse response = null;
        PutMethod putMethod = new PutMethod(BARBICAN_POST_SECRET);

        //Set the header
        Header headerContentType = new Header(REQUEST_HEADER_CONTENT_TYPE, REQUEST_HEADER_CONTENT_TYPE_APP_JSON);
        Header headerProjectId = new Header(REQUEST_HEADER_PROJECT_ID, "123456");
        putMethod.addRequestHeader(headerContentType);
        putMethod.addRequestHeader(headerProjectId);

        //build the JSON representation of the data to be sent to Barbican
        String body = null;
        try {
            body = BarbicanDTO.getBarbicanJsonForRegisterKey(request);
        } catch (JsonProcessingException ex) {
            throw new BarbicanClientException("Unable to construct JSON body for REGISTER request", ex);
        }

        //Construct an entity
        RequestEntity entity;
        try {
            entity = new StringRequestEntity(body, "application/json", "UTF-8");
        } catch (UnsupportedEncodingException e1) {
            throw new BarbicanClientException("Error constructing request body");
        }

        // Set the JSON string of the CreateSecretRequest in the POST body
        putMethod.setRequestEntity(entity);

        // make the PUT request
        try {
            httpClient.executeMethod(putMethod);
            int statusCode = putMethod.getStatusCode();
            if (statusCode != 200) {
                throw new BarbicanClientException("Unable to PUT the key in Barbican");
            }
            String responseBodyAsString = putMethod.getResponseBodyAsString();
            Map<String, String> map = JsonUtil.convertJsonToMap(responseBodyAsString);
            response = new RegisterKeyResponse();
            KeyAttributes attributes = new KeyAttributes();
            attributes.setTransferLink(new URL(map.get("secret_ref")));
            response.getData().add(attributes);
        } catch (HttpException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "HttpException");
            throw barbicanClientException;
        } catch (IOException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "Error communicating with the server");
            throw barbicanClientException;
        }
        return response;
    }

    public DeleteKeyResponse deleteSecret(DeleteKeyRequest request) throws BarbicanClientException {
        DeleteKeyResponse response = null;
        StringBuilder url = new StringBuilder(BARBICAN_POST_SECRET);
        url.append("/");
        url.append(request.getKeyId());
        DeleteMethod deleteMethod = new DeleteMethod(url.toString());

        //Set the header
        Header headerContentType = new Header(REQUEST_HEADER_CONTENT_TYPE, REQUEST_HEADER_CONTENT_TYPE_APP_JSON);
        Header headerProjectId = new Header(REQUEST_HEADER_PROJECT_ID, "123456");
        deleteMethod.addRequestHeader(headerContentType);
        deleteMethod.addRequestHeader(headerProjectId);

        // make the DELETE request
        try {
            httpClient.executeMethod(deleteMethod);
            int statusCode = deleteMethod.getStatusCode();
            if (statusCode == 404) {
                throw new BarbicanClientException("Unable to delete the key from Barbican");
            }
            String responseBodyAsString = deleteMethod.getResponseBodyAsString();
            response = new DeleteKeyResponse();
            response.getHttpResponse().setStatusCode(statusCode);
        } catch (HttpException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "HttpException");
            throw barbicanClientException;
        } catch (IOException e) {
            BarbicanClientException barbicanClientException = new BarbicanClientException(
                    "Error communicating with the server");
            throw barbicanClientException;
        }
        return response;
    }

}
