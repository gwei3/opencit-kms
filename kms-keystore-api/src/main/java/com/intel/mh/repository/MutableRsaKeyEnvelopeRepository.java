/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import java.io.IOException;

/**
 *
 * @author jbuhacoff
 */
public interface MutableRsaKeyEnvelopeRepository extends RsaKeyEnvelopeRepository {
    void addRsaKeyEnvelope(String alias, RsaKeyEnvelope envelope) throws IOException;
    void removeRsaKeyEnvelope(String alias) throws IOException;
}
