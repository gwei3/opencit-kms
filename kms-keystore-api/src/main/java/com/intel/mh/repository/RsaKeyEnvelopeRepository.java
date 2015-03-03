/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import com.intel.dcsg.cpg.crypto.file.RsaKeyEnvelope;
import java.io.IOException;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public interface RsaKeyEnvelopeRepository {
    List<String> listRsaKeyEnvelopes() throws IOException;
    RsaKeyEnvelope getRsaKeyEnvelope(String alias) throws IOException;
}
