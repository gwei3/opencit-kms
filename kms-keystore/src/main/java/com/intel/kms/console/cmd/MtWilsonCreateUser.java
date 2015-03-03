/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.console.cmd;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.console.input.Input;
import com.intel.mh.repository.ServerFileRepository;
//import org.apache.commons.configuration.Configuration;
import com.intel.mtwilson.KeystoreUtil;
import com.intel.dcsg.cpg.io.FileResource;
import com.intel.mtwilson.Folders;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.configuration.ConfigurationProvider;
import com.intel.mtwilson.configuration.EncryptedConfigurationProvider;
import java.io.File;
import java.net.URL;

/**
 * How to run this command to create a data encryption key with alias "test1":
 * 
 * java -jar client-0.1-SNAPSHOT-with-dependencies.jar MtWilsonCreateuser "Username"
 * 
 * It will prompt you for a password to protect the new key that is created. You can automate it
 * by setting the password in an environment variable of your choice (for example, MTWILSON_PASSWORD) and
 * then passing its name with the option  --env-password MTWILSON_PASSWORD
 * 
 * 
 * @author jbuhacoff
 */
public class MtWilsonCreateUser extends InteractiveCommand {

    @Override
    public void execute(String[] args) throws Exception {
//        Configuration options = getOptions();
        ServerFileRepository repository = new ServerFileRepository(Folders.application()+File.separator+"repository");
        repository.open();

//        String password = getNewPassword("the Mt Wilson API Client", "env-password");
//        String password = getExistingPassword("the Server Configuration File", "env-password");
//        EncryptedConfigurationProvider provider = new EncryptedConfigurationProvider(password);
        ConfigurationProvider provider = ConfigurationFactory.getConfigurationProvider();  // the provider now gets the password from MTWILSON_PASSWORD or KMS_PASSWORD etc. automatically
        Configuration serverConfig = provider.load();
        
        String mtwilsonUsername;
        if( args.length < 1) { 
            if( serverConfig.keys().contains("mtwilson.api.username") ) {
                mtwilsonUsername = serverConfig.get("mtwilson.api.username");
            }
            else {
                //throw new IllegalArgumentException("Usage: MtWilsonCreateUser <username> [--env-password CONFIG_PASSWD]"); 
                System.out.println("Usage: MtWilsonCreateUser <username> [--env-password CONFIG_PASSWD]");
                mtwilsonUsername = Input.getRequiredStringWithPrompt("Username for Mt Wilson registration");
            }
        }
        else {
             mtwilsonUsername = args[0];   
        }
        
        
        String mtwilsonUrlStr = serverConfig.get("mtwilson.api.url");
        URL mtwilsonUrl;
        String mtwilsonPassword = serverConfig.get("mtwilson.api.password");
        
        if( mtwilsonUrlStr == null ) {
            mtwilsonUrl = Input.getRequiredURLWithPrompt("Mt Wilson API");
        }
        else {
            mtwilsonUrl = Input.getRequiredURLWithDefaultPrompt("Mt Wilson API", mtwilsonUrlStr);
        }
        
        FileResource resource = new FileResource(new File(repository.getMtWilsonClientKeystorePath()));
        KeystoreUtil.createUserInResource(resource, mtwilsonUsername, mtwilsonPassword, mtwilsonUrl, new String[] { "Attestation" });
        
        serverConfig.set("mtwilson.api.url", mtwilsonUrl.toString());
        serverConfig.set("mtwilson.api.password", mtwilsonPassword);
        
        provider.save(serverConfig);
        
        System.out.println(String.format("Created Mt Wilson user"));
    }
    
}
