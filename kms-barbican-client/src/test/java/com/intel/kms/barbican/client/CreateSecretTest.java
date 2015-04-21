package com.intel.kms.barbican.client;

import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.api.KeyManager;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.BarbicanHttpClient;
import java.io.IOException;
import java.security.KeyStoreException;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;
import org.junit.runner.RunWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({ BarbicanHttpClient.class })

public class CreateSecretTest {

    @Test
    public void testInvalidRequest() throws IOException, KeyStoreException {
        CreateKeyRequest request = new CreateKeyRequest();
        KeyManager kmsManager = new BarbicanKeyManager();
        CreateKeyResponse response = kmsManager.createKey(request);
        assertNotNull("request is invalid", response.getFaults());
    }

    @Test
    public void testValidRequest() throws BarbicanClientException, IOException, KeyStoreException {                
        KeyAttributes expectedKA = new KeyAttributes();
        expectedKA.setTransferPolicy("URL_TO_TRANSFER_POCLIY");
        CreateKeyResponse expectedResponse = new CreateKeyResponse(expectedKA);
        CreateKeyRequest request = new CreateKeyRequest();
        BarbicanHttpClient mockBHC = mock(BarbicanHttpClient.class);
        PowerMockito.mockStatic(BarbicanHttpClient.class);
        PowerMockito.when(BarbicanHttpClient.getBarbicanHttpClient()).thenReturn(mockBHC);
        when(mockBHC.createSecret(request)).thenReturn(expectedResponse);
        
        request.setAlgorithm("AES");
        request.setKeyLength(128);
        request.setMode("OFB");

        KeyManager kmsManager = new BarbicanKeyManager();
        CreateKeyResponse response = kmsManager.createKey(request);

        assertEquals("Valid response as request is valid", expectedResponse,
                response);
    }
}
