/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.setup;

import com.intel.mtwilson.setup.AbstractSetupTask;

/**
 * Very similar to Trust Agent's CreateTlsKeypair SetupTask
 * 
 * @author jbuhacoff
 */
public class Jetty extends AbstractSetupTask {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Jetty.class);
    
    // configuration keys
    public static final String JETTY_PORT = "jetty.port";
    public static final String JETTY_SECURE_PORT = "jetty.secure.port";
    
    private Integer httpPort;
    private Integer httpsPort;
    
    @Override
    protected void configure() throws Exception {
        httpPort = Integer.valueOf(getConfiguration().get(JETTY_PORT, "80"));
        httpsPort = Integer.valueOf(getConfiguration().get(JETTY_SECURE_PORT, "443"));
    }

    @Override
    protected void validate() throws Exception {
        if( getConfiguration().get(JETTY_PORT) == null ) {
            validation("HTTP port is not set");
        }
        if( getConfiguration().get(JETTY_SECURE_PORT) == null ) {
            validation("HTTPS port is not set");
        }
    }

    @Override
    protected void execute() throws Exception {
        getConfiguration().set(JETTY_PORT, httpPort.toString());
        getConfiguration().set(JETTY_SECURE_PORT, httpsPort.toString());
    }
    
    
   
}
