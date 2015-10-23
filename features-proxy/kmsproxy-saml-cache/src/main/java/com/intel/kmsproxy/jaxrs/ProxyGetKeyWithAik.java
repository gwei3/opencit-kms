/*
 * Copyright (C) 2014 Intel Corporation
 * All rights reserved.
 */
package com.intel.kmsproxy.jaxrs;

import com.intel.dcsg.cpg.crypto.CryptographyException;
import com.intel.dcsg.cpg.crypto.RsaUtil;
import com.intel.dcsg.cpg.crypto.Sha1Digest;
import com.intel.dcsg.cpg.io.pem.Pem;
import com.intel.dcsg.cpg.x509.X509Util;
import com.intel.kmsproxy.MtWilsonV2Client;
import com.intel.kmsproxy.cache.DirectoryTrustReportCache;
import com.intel.mtwilson.api.ApiException;
import com.intel.mtwilson.api.ClientException;
import com.intel.mtwilson.collection.MultivaluedHashMap;
import com.intel.mtwilson.jaxrs2.mediatype.CryptoMediaType;
import com.intel.mtwilson.launcher.ws.ext.V2;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Enumeration;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.PostMethod;
import org.apache.commons.httpclient.methods.StringRequestEntity;

/**
 *
 * @author jbuhacoff
 */
@V2
@Path("/keys")
public class ProxyGetKeyWithAik {
    
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(ProxyGetKeyWithAik.class);
   
    /**
     * Example request:
     *
     * <pre>
     * curl --verbose --insecure -X POST
     * -H "Content-Type: application/x-pem-file"
     * -H "Accept: application/octet-stream"
     * --data-binary
     *
     * @/etc/intel/cloudsecurity/cert/aikpubkey.pem
     * http://keyserver/v1/keys/testkey2
     * </pre>
     *
     * Where the contents of /etc/intel/cloudsecurity/cert/aikpubkey.pem are:      <pre>
     * -----BEGIN PUBLIC KEY-----
     * MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp7LLuu74Grs1FVlpZ3JE
     * nedg8zl3v2vV+Elui6PjTZxpez7veAOvBbQ2qaMbDe40fnrFRttnpLkhHZtYyJB0
     * c9P4XRYqOYsymNZpnbTDhZGLP3LsvvTWgZs/Sxwpthwv9+S/Tnxl+inLwWGCU98e
     * IN+hoeSoYQoKubR4b2teQBKhQd32ov7yUznOZj07I5IJFKLTEo8aJjLeupNcXWLa
     * 90CuievTv6f8Zt2CvSJJmM0FlGWgGu1ypZD/yu8DgfzcuAruQreu+aHsd2HD49nL
     * 8Dp+SkI0qI7gn8+zYpjojukRxazRY1KkCIX1MJ+wjVDjQ2QJBBgxIT8aOKcAfxT6
     * wwIDAQAB
     * -----END PUBLIC KEY-----
     * </pre>
     *
     * The response content type is determined by the client's Accept header and
     * the remote key server's supported options.
     *
     * @param keyId
     * @param pem
     * @return
     */
    @POST
    @Path("/{keyId: [0-9a-zA-Z_-]+}/transfer")
    @Consumes(CryptoMediaType.APPLICATION_X_PEM_FILE)
    public byte[] getKey(@PathParam("keyId") String keyId, String pem, @Context HttpServletRequest httpRequest, @Context HttpServletResponse httpResponse) {
        log.debug("ProxyGetKeyWithAik");
        log.debug("Method: {}", httpRequest.getMethod()); // example:  POST
        log.debug("Scheme: {}", httpRequest.getScheme()); // example:  http
        log.debug("RequestURL: {}", httpRequest.getRequestURL()); // example:  http://10.255.72.191/v1/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("RequestURI: {}", httpRequest.getRequestURI()); // example:  /v1/keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("ServerName: {}", httpRequest.getServerName()); // example:  10.255.72.191
        log.debug("ServerPort: {}", httpRequest.getServerPort()); // example:  80
        log.debug("ContextPath: {}", httpRequest.getContextPath()); // example:  (blank)
        log.debug("PathInfo: {}", httpRequest.getPathInfo()); // example:  /keys/3787f629-1827-411e-866e-ce87e37f805a/transfer
        log.debug("PathTranslated: {}", httpRequest.getPathTranslated()); // example:  C:\Users\jbuhacof\workspace\dcg_security-kms\kms-html5\src\main\resources\www\keys\3787f629-1827-411e-866e-ce87e37f805a\transfer
        log.debug("RemoteAddr: {}", httpRequest.getRemoteAddr()); // example:  10.1.71.180
        log.debug("ServletPath: {}", httpRequest.getServletPath()); // example:  /v1

        try {
            Pem pemObject = Pem.valueOf(pem);
            if (pemObject.getBanner().equals("PUBLIC KEY")) {
                log.debug("Input is public key");
//                PublicKey aikPublicKey = RsaUtil.decodePemPublicKey(pem);
                PublicKey aikPublicKey = RsaUtil.decodeDerPublicKey(pemObject.getContent());
                Sha1Digest aikId = Sha1Digest.digestOf(aikPublicKey.getEncoded());
                log.debug("Extracted AIK public key from PEM file");
                ProxyResponse backendResponse = proxyKeyRequestByAik(keyId, aikId, httpRequest);
                prepareResponse(httpResponse, backendResponse);
                return backendResponse.content;
            } else if (pemObject.getBanner().equals("CERTIFICATE")) {
                log.debug("Input is certificate");
//                X509Certificate aikcert = X509Util.decodePemCertificate(pem);
                X509Certificate aikCertificate = X509Util.decodeDerCertificate(pemObject.getContent());
                Sha1Digest aikId = Sha1Digest.digestOf(aikCertificate.getPublicKey().getEncoded());
                ProxyResponse backendResponse = proxyKeyRequestByAik(keyId, aikId, httpRequest);
                prepareResponse(httpResponse, backendResponse);
                return backendResponse.content;
            } else {
                throw new WebApplicationException("AIK public key or certificate required", 400);
            }
        } catch (CryptographyException | ClientException | ApiException | GeneralSecurityException | IOException e) {
            throw new WebApplicationException("Cannot retrieve key", e);
        }
    }
    
    private void prepareResponse(HttpServletResponse httpResponse, ProxyResponse backendResponse) {
        // copy all response headers from key server to our response, should include content type
        for (String headerName : backendResponse.headers.keys()) {
            for (String headerValue : backendResponse.headers.get(headerName)) {
                log.debug("Adding response header {}: {}", headerName, headerValue);
                httpResponse.addHeader(headerName, headerValue);
            }
        }        
    }
    
    private static class ProxyResponse {

        byte[] content = null;
        MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();
    }
    
    private ProxyResponse proxyKeyRequestByAik(String keyId, Sha1Digest aikId, HttpServletRequest request) throws CryptographyException, ClientException, ApiException, GeneralSecurityException, IOException {
        log.debug("proxyKeyRequestByAik for keyId: {}, aikId: {}", keyId, aikId.toHexString());
//            HostTrustResponse hostTrustResponse = api.getHostTrustByAik(new com.intel.mtwilson.model.Sha1Digest(aikId.toByteArray()));  // convert from cpg-crypto Sha1Digest to mtwilson-crypto Sha1Digest, needed until Mt Wilson is updated to use cpg-crypto
//            log.debug("trust status for {}", hostTrustResponse.hostname.toString());
//            log.debug("bios: {}", hostTrustResponse.trust.bios);
//            log.debug("vmm: {}", hostTrustResponse.trust.vmm);
        DirectoryTrustReportCache trustReportCache = new DirectoryTrustReportCache();
        
        String saml;

        // first try the cache
        try {
            saml = trustReportCache.getAssertionForSubject(aikId.toHexString());
        } catch (IOException e) {
            log.error("Cannot check trust report cache for aik {}", aikId.toHexString(), e);
            saml = null;
        }
        
        if (saml == null) {
            try {
        // 1. call mtwilson to get SAML report
                MtWilsonV2Client client = new MtWilsonV2Client();
                saml = client.getAssertionForSubject(aikId.toHexString());
                if( saml != null ) {
                    // store it in cache
                    trustReportCache.storeAssertion(aikId.toHexString(), saml);
                }
            } catch (IOException e) {
                log.error("Cannot get SAML report for aik",aikId.toHexString(), e);
                /*
                if (e.getHttpStatusCode() == 404) {
                    log.error("No SAML report available for AIK {}", aikId.toHexString());
                    // no SAML report for the specified host means we don't release the key - regardless of whether the key actually exists or not
                    throw new WebApplicationException(Status.UNAUTHORIZED);
                }
                // for anything else, we just echo the mtwilson status code and text
                throw new WebApplicationException(e.getHttpReasonPhrase(), e.getHttpStatusCode());
                * */
                throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
            }
        }
        // 2. post SAML report to original URL, capture result

        // create  http client for request.getRequestURL()  , post the saml content and fwd same accept header provided by client
        log.debug("proxyKeyRequestByAik to key server: {}", request.getRequestURL().toString());
        HttpClient client = new HttpClient();
        PostMethod post = new PostMethod(request.getRequestURL().toString());
        
        log.debug("proxyKeyRequestByAik POST URI: {}", post.getURI().toString());

        // we need to copy AT LEAST the "Accept" header, but since we're a proxy we should copy ALL the headers
        Enumeration<String> headerNames = request.getHeaderNames();
        if (headerNames != null) {
            for (String headerName : Collections.list(headerNames)) {
                log.debug("proxyKeyRequestByAik adding header {}: {}", headerName, request.getHeader(headerName));
                post.addRequestHeader(headerName, request.getHeader(headerName));
//                    post.addRequestHeader("Accept", request.getHeader("Accept"));
            }
        }

        // remove the client's Content-Type and Content-Length headers because
        // we are replacing the message body with the SAML report, and keeping
        // these headers would result in either 415 Unsupported Media Type or
        // truncated message at server (due to incorrect content-length)
        post.removeRequestHeader("Content-Type"); // post.setRequestHeader("Content-Type", CryptoMediaType.APPLICATION_SAML);
        post.removeRequestHeader("Content-Length");
        
        post.setRequestEntity(new StringRequestEntity(saml, CryptoMediaType.APPLICATION_SAML, "UTF-8"));
        
        int status = client.executeMethod(post);
        if (status != HttpStatus.SC_OK) {
            log.error("proxyKeyRequestByAik got error response from key server: {} {}", post.getStatusCode(), post.getStatusText());
            // forward the remote error to the client with same code and status text;  currently not forwarding the response body 
            throw new WebApplicationException(post.getStatusText(), status);
        }
        
        ProxyResponse response = new ProxyResponse();
        response.content = post.getResponseBody();

        // copy all response headaers, including content type
        for (Header header : post.getResponseHeaders()) {
            response.headers.add(header.getName(), header.getValue());
            log.debug("proxyKeyRequestByAik got response header {}: {}", header.getName(), header.getValue());
        }

//        response.contentType = post.getResponseHeader("Content-Type").getValue();

        post.releaseConnection();

        // 3. return result to client as-is
        return response;
    }
}
