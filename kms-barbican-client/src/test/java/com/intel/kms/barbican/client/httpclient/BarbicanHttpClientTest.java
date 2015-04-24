package com.intel.kms.barbican.client.httpclient;

import com.intel.dcsg.cpg.configuration.CommonsConfiguration;
import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.api.CreateOrderRequest;
import com.intel.kms.barbican.api.CreateOrderResponse;
import com.intel.kms.barbican.api.GetOrderRequest;
import com.intel.kms.barbican.api.GetOrderResponse;
import com.intel.kms.barbican.api.TransferSecretRequest;
import com.intel.kms.barbican.api.TransferSecretResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.rs.Orders;
import com.intel.kms.barbican.client.httpclient.rs.Secrets;
import com.intel.kms.barbican.client.util.BarbicanApiUtil;
import org.apache.commons.configuration.BaseConfiguration;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mockito;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

@RunWith(PowerMockRunner.class)
@PrepareForTest({BarbicanApiUtil.class, BarbicanHttpClient.class})

public class BarbicanHttpClientTest {

    Configuration config;
    Orders mockOrders;
    Secrets mockSecrets;
    CreateKeyRequest mockCreateKeyRequest;
    CreateOrderRequest mockOrderRequest;
    CreateOrderResponse mockOrderResponse;
    GetOrderResponse mockGetOrderResponse;
    GetOrderRequest mockGetOrderRequest;
    TransferKeyRequest mockTransferKeyRequest;
    TransferKeyResponse mockTransferKeyResponse;
    TransferSecretResponse mockTransferSecretResponse;
    TransferSecretRequest mockTransferSecretRequest;
    RegisterKeyRequest mockRegisterKeyRequest;
    RegisterKeyResponse mockRegisterKeyResponse;

    BarbicanHttpClient barbicanHttpClient;

    @Before
    public void setup() throws Exception {
        org.apache.commons.configuration.Configuration apacheConfig = new BaseConfiguration();
        config = new CommonsConfiguration(apacheConfig);
        config.set("endpoint.url", "http://127.0.0.1:8080/");
        config.set("x_PROJECT-ID", "PROJECT_ID");

        mockOrders = Mockito.mock(Orders.class);
        mockSecrets = Mockito.mock(Secrets.class);
        PowerMockito.whenNew(Orders.class).withAnyArguments().thenReturn(mockOrders);
        PowerMockito.whenNew(Secrets.class).withAnyArguments().thenReturn(mockSecrets);
        barbicanHttpClient = new BarbicanHttpClient(config);

        barbicanHttpClient.setOrders(mockOrders);
        barbicanHttpClient.setSecrets(mockSecrets);
        PowerMockito.mockStatic(BarbicanApiUtil.class);

        mockCreateKeyRequest = Mockito.mock(CreateKeyRequest.class);
        mockOrderRequest = Mockito.mock(CreateOrderRequest.class);
        mockOrderResponse = Mockito.mock(CreateOrderResponse.class);
        mockGetOrderRequest = Mockito.mock(GetOrderRequest.class);
        mockGetOrderResponse = Mockito.mock(GetOrderResponse.class);
        mockRegisterKeyRequest = Mockito.mock(RegisterKeyRequest.class);
        mockRegisterKeyResponse = Mockito.mock(RegisterKeyResponse.class);

        mockTransferKeyRequest = Mockito.mock(TransferKeyRequest.class);
        mockTransferKeyResponse = Mockito.mock(TransferKeyResponse.class);
        mockTransferSecretResponse = Mockito.mock(TransferSecretResponse.class);
        mockTransferSecretRequest = Mockito.mock(TransferSecretRequest.class);

        mockOrderResponse.order_ref = "http://localhost:8080/v1/orders/ORDER_ID";

        mockGetOrderResponse.secret_ref = "http://localhost:8080/v1/secrets/SECRET_ID";

        PowerMockito.whenNew(GetOrderRequest.class).withAnyArguments().thenReturn(mockGetOrderRequest);
        PowerMockito.whenNew(TransferKeyRequest.class).withAnyArguments().thenReturn(mockTransferKeyRequest);
        PowerMockito.when(BarbicanApiUtil.mapCreateKeyRequestToCreateOrderRequest(mockCreateKeyRequest)).thenReturn(mockOrderRequest);
        PowerMockito.when(BarbicanApiUtil.mapTransferKeyRequestToTransferSecretRequest(mockTransferKeyRequest)).thenReturn(mockTransferSecretRequest);
        PowerMockito.when(BarbicanApiUtil.mapTransferSecretResponseToTransferKeyResponse(mockTransferSecretResponse)).thenReturn(mockTransferKeyResponse);

        PowerMockito.when(mockOrders.createOrderRequest(mockOrderRequest)).thenReturn(mockOrderResponse);
        PowerMockito.when(mockOrders.getOrderRequest(mockGetOrderRequest)).thenReturn(mockGetOrderResponse);
        PowerMockito.when(mockSecrets.transferSecret(mockTransferSecretRequest)).thenReturn(mockTransferSecretResponse);

    }

    @Test
    public void testCreateKeyHappyPath() throws Exception {
        TransferKeyResponse transferKeyResponse = barbicanHttpClient.createSecret(mockCreateKeyRequest);
        Assert.assertTrue(true);
    }
    
    
    @Test
    public void testRetrieveSecretHappyPath() throws Exception {
        TransferKeyResponse transferKeyResponse = barbicanHttpClient.retrieveSecret(mockTransferKeyRequest);
        Assert.assertTrue(true);
    }
    
    @Test
    public void testRegisterSecret() throws BarbicanClientException{
        RegisterKeyResponse registerSecret = barbicanHttpClient.registerSecret(mockRegisterKeyRequest);
    }

}
