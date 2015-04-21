package com.intel.kms.barbican.client;

import com.intel.kms.api.KeyManager;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import java.io.IOException;
import java.security.KeyStoreException;
import org.junit.Assert;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class TransferTest {

    @Test
    public void testInvalidRequest() throws IOException, KeyStoreException {
        TransferKeyRequest request = new TransferKeyRequest();
        request.setKeyId(null);
        KeyManager kmsManager = new BarbicanKeyManager();
        TransferKeyResponse response = kmsManager.transferKey(request);
        assertNotNull("request is invalid", response.getFaults());
    }

    @Test
    public void testValidRequest() throws IOException, KeyStoreException {
        TransferKeyRequest request = new TransferKeyRequest();
        request.setKeyId("KEY_ID");

        KeyManager kmsManager = new BarbicanKeyManager();
        TransferKeyResponse response = kmsManager.transferKey(request);
        TransferKeyResponse expectedResponse = new TransferKeyResponse();
        expectedResponse.setKey(new byte[]{});
        Assert.assertArrayEquals("Valid response as request is valid", expectedResponse.getKey(),
                response.getKey());
    }
}
