/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jaxrs;

import com.intel.dcsg.cpg.extensions.Extensions;
import com.intel.kms.api.KeyManager;

/**
 *
 * @author jbuhacoff
 */
public abstract class AbstractEndpoint {
    private KeyManager keyRepository;
    
    public AbstractEndpoint() {
        /**
         * get the key repository "driver" since there can be only one 
         * configured key repository: local directory, kmip, or barbican. 
         * it's a global setting.
         */
        keyRepository = Extensions.require(KeyManager.class);
    }
    
    public KeyManager getKeyRepository() { return keyRepository; }
}
