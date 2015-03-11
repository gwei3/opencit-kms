/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.configuration.PropertiesConfiguration;
import com.intel.dcsg.cpg.crypto.RandomUtil;
import com.intel.kms.setup.EnvelopeKey;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.setup.SetupTask;
import com.intel.mtwilson.setup.console.cmd.Setup;
import com.intel.mtwilson.setup.console.cmd.SetupManager;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import org.apache.commons.configuration.ConfigurationException;
import org.junit.BeforeClass;
import org.junit.Test;
import com.intel.kms.setup.PasswordVault;

/**
 * User stories:
 * As a client, I am able to register an existing key for storage.
 * 
 * @author jbuhacoff
 */
public class ClientRegisterKeyTest {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ClientRegisterKeyTest.class);

    /**
     * Test environment outline:
     * 1. Set system property mtwilson.environment.prefix to random value;
     *    This means all Environment calls will fail to get any values and all
     *    components will use fallback values.
     *    This will avoid collision with developer local environment.
     * 2. Set system property mtwilson.application.id to random value
     *    This allows the application folder to be set inside the target folder.
     * 3. Set system property (testid).home to be inside the target folder.
     * 4. Set system property mtwilson.configuration.file to be test.properties
     * 
     * Folder locations need to be set to target folder
     */
    @BeforeClass
    public static void initializeTestEnvironment() throws IOException, ConfigurationException {
        String testId = RandomUtil.randomHexString(4);
        File testdir = new File("target"+File.separator+"test-data"+File.separator+testId);
        log.debug("Test directory: {}", testdir.getAbsolutePath());
        testdir.mkdirs();
        
        System.setProperty("mtwilson.environment.prefix", "TEST_"+testId+"_");
        System.setProperty("mtwilson.application.id", "test-"+testId);
        System.setProperty("mtwilson.configuration.file", "test.properties");
        System.setProperty("test-"+testId+".home", testdir.getAbsolutePath());
        
        // configuration
        File configurationFile = ConfigurationFactory.getConfigurationFile();
        configurationFile.getParentFile().mkdirs();
        
        log.debug("Test configuration file: {}", configurationFile.getAbsolutePath());
        // create a configuration file with a random master password
        PropertiesConfiguration testconfig = new PropertiesConfiguration();
        testconfig.set("password.vault.key", testId);
        
        try(FileOutputStream out = new FileOutputStream(configurationFile)) {
            testconfig.getProperties().store(out, String.format("test id: %s", testId));
        }
        
        runSetupTasks(testconfig);
        
    }
    
    protected static void runSetupTasks(Configuration configuration) throws IOException, ConfigurationException {
        ArrayList<SetupTask> tasks = new ArrayList<>();
        tasks.add(new PasswordVault());
        tasks.add(new EnvelopeKey());
        Setup manager = new Setup();
        manager.setOptions(new org.apache.commons.configuration.PropertiesConfiguration());
        manager.execute(tasks);
    }
    
    /**
     * Administrator work outline (setup):
     * 1. setup task creates a public key for receiving key registrations
     * 2. administrator grants permission for client to register existing keys
     * 3. administrator provides the kms registration public key to client
     * Client work outline (request):
     * 1. client generates/loads existing key to register
     * 2. client wraps existing key with kms registration public key
     * 3. client sends wrapped key to kms
     * Server work outline (response):
     * 1. Load kms registration public key identified in request
     * 2. Unwrap wrapped key using kms registration public key
     * 3. Validate unwrapped key attributes
     * 4. Wrap key for storage using kms storage key
     * 5. Store key
     * 6. Send register key response object with registered key attributes
     */
    @Test
    public void registerKeyTest() throws IOException {
        // setup
    }
}
