package com.intel.kms.barbican.client;

import com.intel.dcsg.cpg.validation.Fault;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.CreateKeyResponse;
import com.intel.kms.api.DeleteKeyRequest;
import com.intel.kms.api.DeleteKeyResponse;
import com.intel.kms.api.GetKeyAttributesRequest;
import com.intel.kms.api.GetKeyAttributesResponse;
import com.intel.kms.api.KeyManager;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.api.RegisterKeyResponse;
import com.intel.kms.api.SearchKeyAttributesRequest;
import com.intel.kms.api.SearchKeyAttributesResponse;
import com.intel.kms.api.TransferKeyRequest;
import com.intel.kms.api.TransferKeyResponse;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.kms.barbican.client.httpclient.BarbicanHttpClient;
import com.intel.kms.barbican.client.validate.RequestValidator;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation for a south-bound Barbican specific adapter.
 *
 * @author Siddharth
 *
 */
public class BarbicanKeyManager implements KeyManager {

    private static final Logger log = LoggerFactory.getLogger(BarbicanKeyManager.class);

    public BarbicanKeyManager() {
    }

    /**
     * Call out the barbican rest API to create a new secret
     *
     * @param request
     * @return
     */
    @Override
    public CreateKeyResponse createKey(CreateKeyRequest request) {
        CreateKeyResponse response = new CreateKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateCreateKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            response = BarbicanHttpClient.getBarbicanHttpClient().createSecret(
                    request);
        } catch (BarbicanClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    /**
     * Method to put an already available key into barbican
     *
     * @param request
     * @return RegisterKeyResponse
     */
    @Override
    public RegisterKeyResponse registerKey(RegisterKeyRequest request) {
        RegisterKeyResponse response = new RegisterKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateRegisterKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            response = BarbicanHttpClient.getBarbicanHttpClient().registerSecret(request);
        } catch (BarbicanClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    @Override
    public DeleteKeyResponse deleteKey(DeleteKeyRequest request) {
        DeleteKeyResponse response = new DeleteKeyResponse();
        // validate the input request
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateDeleteKey(request));
        if (!faults.isEmpty()) {
            response.getFaults().addAll(faults);
            return response;
        }

        try {
            response = BarbicanHttpClient.getBarbicanHttpClient().deleteSecret(request);
        } catch (BarbicanClientException e) {
            faults.add(new Fault(e, "Error occurred while creating key in barbican"));
            response.getFaults().addAll(faults);
        }
        return response;
    }

    /**
     * Call out the barbican rest API to transfer/retrieve/get a secret by the
     * secret ID from the meta data
     *
     * @param request
     * @return
     */
    @Override
    public TransferKeyResponse transferKey(TransferKeyRequest request) {
        TransferKeyResponse response = null;
        List<Fault> faults = new ArrayList<>();
        faults.addAll(RequestValidator.validateTransferKey(request));
        if (!faults.isEmpty()) {
            response = new TransferKeyResponse();
            response.getFaults().addAll(faults);
            return response;
        }

        response = new TransferKeyResponse();
        response.setKey(new byte[]{});
        return response;
    }

    @Override
    public GetKeyAttributesResponse getKeyAttributes(GetKeyAttributesRequest keyAttributesRequest) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public SearchKeyAttributesResponse searchKeyAttributes(SearchKeyAttributesRequest searchKeyAttributesRequest) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
