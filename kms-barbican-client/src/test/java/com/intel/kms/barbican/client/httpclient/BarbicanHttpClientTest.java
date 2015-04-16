package com.intel.kms.barbican.client.httpclient;

import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.KeyAttributes;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import java.io.IOException;
import java.net.URL;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpException;
import org.apache.commons.httpclient.methods.PostMethod;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({BarbicanHttpClient.class})
public class BarbicanHttpClientTest {

    @Test
    public void testCreateSecretHappyPath() throws Exception {
        KeyAttributes expectedKA = new KeyAttributes();
        expectedKA.setTransferLink(new URL("http://barbicanserver/transferLink"));
        CreateKeyResponse expectedResponse = new CreateKeyResponse(expectedKA);

        HttpClient mockHttpClient = Mockito.mock(HttpClient.class);
        final PostMethod mockPostMethod = Mockito.mock(PostMethod.class);

        Mockito.when(mockHttpClient.executeMethod(mockPostMethod)).thenAnswer(
                new Answer<Integer>() {
                    @Override
                    public Integer answer(InvocationOnMock invocation)
                    throws Throwable {
                        return 111;
                    }
                });

        PowerMockito.whenNew(PostMethod.class).withAnyArguments()
                .thenReturn(mockPostMethod);

        BarbicanHttpClient barbicanHttpClient = BarbicanHttpClient
                .getBarbicanHttpClient();
        barbicanHttpClient.setHttpClient(mockHttpClient);

        Mockito.when(mockPostMethod.getResponseBodyAsString()).thenAnswer(
                new Answer<String>() {

                    @Override
                    public String answer(InvocationOnMock invocation)
                    throws Throwable {
                        return "{\"secret_ref\": \"http://barbicanserver/transferLink\"}";
                    }
                });

        CreateKeyResponse createSecretResponse = barbicanHttpClient
                .createSecret(new CreateKeyRequest());
        
        assertEquals("Success", expectedKA.getTransferLink(), createSecretResponse.getData().get(0).getTransferLink());

    }

    @Test(expected = BarbicanClientException.class)
    public void testCreateSecretWithHttpException() throws Exception {
        HttpClient mockHttpClient = Mockito.mock(HttpClient.class);
        final PostMethod mockPostMethod = Mockito.mock(PostMethod.class);

        Mockito.when(mockHttpClient.executeMethod(mockPostMethod)).thenThrow(
                new HttpException());

        PowerMockito.whenNew(PostMethod.class).withAnyArguments()
                .thenReturn(mockPostMethod);

        BarbicanHttpClient barbicanHttpClient = BarbicanHttpClient
                .getBarbicanHttpClient();
        barbicanHttpClient.setHttpClient(mockHttpClient);

        barbicanHttpClient.createSecret(new CreateKeyRequest());

    }

    @Test(expected = BarbicanClientException.class)
    public void testCreateSecretWithIOException() throws Exception {
        HttpClient mockHttpClient = Mockito.mock(HttpClient.class);
        final PostMethod mockPostMethod = Mockito.mock(PostMethod.class);

        Mockito.when(mockHttpClient.executeMethod(mockPostMethod)).thenThrow(
                new IOException());

        PowerMockito.whenNew(PostMethod.class).withAnyArguments()
                .thenReturn(mockPostMethod);

        BarbicanHttpClient barbicanHttpClient = BarbicanHttpClient
                .getBarbicanHttpClient();
        barbicanHttpClient.setHttpClient(mockHttpClient);

        barbicanHttpClient.createSecret(new CreateKeyRequest());

    }

    @Test(expected = BarbicanClientException.class)
    public void testCreateSecretWithErrorRequestObject() throws Exception {
        BarbicanHttpClient barbicanHttpClient = BarbicanHttpClient
                .getBarbicanHttpClient();
        barbicanHttpClient.createSecret(null);

    }

}
