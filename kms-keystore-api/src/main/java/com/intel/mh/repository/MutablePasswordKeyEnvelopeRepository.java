/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.file.PasswordKeyEnvelope;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public interface MutablePasswordKeyEnvelopeRepository extends PasswordKeyEnvelopeRepository {
    void addPasswordKeyEnvelope(String alias, PasswordKeyEnvelope envelope) throws IOException;
    void removePasswordKeyEnvelope(String alias) throws IOException;
}
