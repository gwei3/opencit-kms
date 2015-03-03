/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import java.io.IOException;
import java.security.cert.X509Certificate;

/**
 *
 * @author jbuhacoff
 */
public interface MutableX509CertificateRepository extends RsaKeyEnvelopeRepository {
    void addX509Certificate(String alias, X509Certificate envelope) throws IOException;
    void removeX509Certificate(String alias) throws IOException;
}
