/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.intel.kms.barbican.client.dto;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.intel.kms.api.CreateKeyRequest;
import com.intel.kms.api.KeyDescriptor;
import com.intel.kms.api.RegisterKeyRequest;
import com.intel.kms.barbican.client.exception.BarbicanClientException;
import com.intel.mtwilson.util.crypto.key2.CipherKeyAttributes;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author soakx
 */
public class BarbicanDTOTest {

    public BarbicanDTOTest() {
    }

    @Test
    public void testGetBarbicanJsonForCreateKey() throws JsonProcessingException {
        CreateKeyRequest request = new CreateKeyRequest();
        request.setKeyLength(256);
        request.setMode("cbc");
        String barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForCreateKey(request);
        assertNotNull("JSON represntation created", barbicanJsonForCreateKey);
        assertEquals("No algorith key in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));
        request.setAlgorithm("AES");
        barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForCreateKey(request);
        assertNotEquals("algorithm key found in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));
    }

    @Test(expected = NullPointerException.class)
    public void testGetBarbicanJsonForRegisterKeyWithNoKeydataSet() throws JsonProcessingException {
        RegisterKeyRequest request = new RegisterKeyRequest();
        KeyDescriptor keyDescriptor = new KeyDescriptor();
        CipherKeyAttributes content = new CipherKeyAttributes();
        content.setKeyLength(256);
        CipherKeyAttributes encryption = new CipherKeyAttributes();
        encryption.setMode("cbc");
        keyDescriptor.setContent(content);
        keyDescriptor.setEncryption(encryption);
        request.setDescriptor(keyDescriptor);
        String barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForRegisterKey(request);
        assertNotNull("JSON represntation created", barbicanJsonForCreateKey);
        assertEquals("No algorith key in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));

        encryption.setAlgorithm("AES");
        barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForRegisterKey(request);
        assertNotEquals("algorithm key found in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));
    }

    @Test
    public void testGetBarbicanJsonForRegisterKey() throws JsonProcessingException {
        RegisterKeyRequest request = new RegisterKeyRequest();
        KeyDescriptor keyDescriptor = new KeyDescriptor();
        CipherKeyAttributes content = new CipherKeyAttributes();
        content.setKeyLength(256);
        CipherKeyAttributes encryption = new CipherKeyAttributes();
        encryption.setMode("cbc");
        keyDescriptor.setContent(content);
        keyDescriptor.setEncryption(encryption);
        request.setKey("KEY_DATA".getBytes());

        request.setDescriptor(keyDescriptor);
        String barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForRegisterKey(request);
        assertNotNull("JSON represntation created", barbicanJsonForCreateKey);
        assertEquals("No algorith key in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));

        encryption.setAlgorithm("AES");
        barbicanJsonForCreateKey = BarbicanDTO.getBarbicanJsonForRegisterKey(request);
        assertNotEquals("algorithm key found in the json", -1, barbicanJsonForCreateKey.indexOf("\"algorithm\""));
    }
}
