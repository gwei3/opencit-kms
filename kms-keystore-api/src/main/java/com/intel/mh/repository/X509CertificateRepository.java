/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.mh.repository;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author jbuhacoff
 */
public interface X509CertificateRepository {
    List<String> listX509Certificates() throws IOException;
    X509Certificate getX509Certificate(String alias) throws IOException;
}
