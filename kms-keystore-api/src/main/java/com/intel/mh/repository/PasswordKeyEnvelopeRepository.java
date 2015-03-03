/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelope;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public interface PasswordKeyEnvelopeRepository {
    List<String> listPasswordKeyEnvelopes() throws IOException;
    PasswordKeyEnvelope getPasswordKeyEnvelope(String alias) throws IOException;
}
