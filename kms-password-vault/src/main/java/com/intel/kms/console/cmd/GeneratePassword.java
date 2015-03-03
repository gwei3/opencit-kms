/*
 * Copyright (C) 2012 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.console.cmd;

import com.intel.dcsg.cpg.console.InteractiveCommand;
import com.intel.dcsg.cpg.crypto.RandomUtil;
/**
 * Generates a 16-byte (default) password.
 * The output will include only ASCII printable characters.
 * 
 * How to run this command:
 * kms generate-password [--length=(#bytes)]
 * 
 * Example output:
 * <pre>
CGaTpWf3YcFeEzyQfxlOAQ==
 * </pre>
 * 
 * This command does not require
 * reading or writing to any configuration or file. The user must copy and 
 * paste the generated password and provide it in an environment 
 * variable when starting the KMS:
 * export KMS_PASSWORD=(generated password here)
 * 
 * @author jbuhacoff
 */
public class GeneratePassword extends InteractiveCommand {

    @Override
    public void execute(String[] args) throws Exception {
        int lengthBytes = options.getInt("length", 16);
        
        char[] password = RandomUtil.randomBase64String(lengthBytes).toCharArray();
        
        System.out.println(password);
    }
    
}
