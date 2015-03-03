/*
 * Copyright (C) 2013 Intel Corporation
 * All rights reserved.
 */
package com.intel.kms.jetty9;

import com.intel.dcsg.cpg.configuration.Configuration;
import com.intel.dcsg.cpg.crypto.key.password.Password;
import com.intel.mtwilson.configuration.EncryptedConfigurationProvider;
import com.intel.kms.setup.Jetty;
import com.intel.kms.setup.JettyTlsKeystore;
import static com.intel.kms.setup.JettyTlsKeystore.JAVAX_NET_SSL_KEYSTOREPASSWORD;
import com.intel.mtwilson.configuration.ConfigurationFactory;
import com.intel.mtwilson.configuration.PasswordVaultFactory;
import com.intel.mtwilson.util.crypto.keystore.PasswordKeyStore;
import java.io.File;
import java.io.IOException;
import java.security.KeyStoreException;
//import org.apache.commons.configuration.Configuration;
//import org.apache.commons.configuration.ConfigurationException;
import org.eclipse.jetty.server.ConnectionFactory;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;

/**
 * How to run the server:
 * 
 * <pre>
 * kms start
 * </pre>
 * 
 * Old way:
 * <pre>
 * java -jar kms-1.0-SNAPSHOT-with-dependencies.jar start
 * </pre>
 * 
 * How to access the server:
 *
 * http://localhost:80/
 *
 *
 * javax.net.ssl.keyStore (no default; must be provided)
 * javax.net.ssl.keyStorePassword  (no default, must be provided)
 * jetty.port  (default 80)
 * jetty.secure.port (default 443)
 * 
 * When using the launcher, export KMS_PASSWORD=password to read the
 * javax.net.ssl.keyStore and .keyStorePassword properties from the
 * encrypted configuration. 
 * 
 * When running independently, you can set those properties on the 
 * java command line with -Djavax.net.ssl.keyStore=keystore.jks and
 * -Djavax.net.ssl.keyStorePassword=password.
 * 
 * @author jbuhacoff
 */
public class StartHttpServer implements Runnable {
    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(StartHttpServer.class);
    
    public final static String JETTY_HYPERTEXT = "jetty.hypertext"; //"JETTY_HYPERTEXT";
    public final static String JETTY_WEBXML = "jetty.webxml"; //"JETTY_WEBXML";
    
    public static final Server jetty = new Server();
    private Configuration configuration;

    public void setConfiguration(Configuration configuration) {
        this.configuration = configuration;
    }

    protected File getKeystoreFile() {
        return new File(configuration.get(JettyTlsKeystore.JAVAX_NET_SSL_KEYSTORE));
    }
    protected Password getKeystorePassword() throws KeyStoreException, IOException {
        try(PasswordKeyStore passwordVault = PasswordVaultFactory.getPasswordKeyStore(configuration)) {
            if( passwordVault.contains(JettyTlsKeystore.JAVAX_NET_SSL_KEYSTOREPASSWORD)) {
            return passwordVault.get(JettyTlsKeystore.JAVAX_NET_SSL_KEYSTOREPASSWORD);
            }
            return null;
        }
    }

    public Integer getHttpPort() {
        return Integer.valueOf(configuration.get(Jetty.JETTY_PORT, "80"));
    }

    public Integer getHttpsPort() {
        return Integer.valueOf(configuration.get(Jetty.JETTY_SECURE_PORT, "443"));
    }

    @Override
    public void run() {
        try {
            configuration = ConfigurationFactory.getConfiguration();
            startJettyHttpServer();
        } catch (IOException e) {
            log.debug("cannot start jetty http server");
            throw new RuntimeException(e);
        }
    }

    // converts forward slashes to the platform's path separator (forward on linux/mac, backslash on windows)
    private String path(String pathForwardSlashes) {
        return pathForwardSlashes.replace("/", File.separator);
    }

    /**
     * Default is used during development so you can run "kms start" from
     * the dcg_security-kms source directory.
     * 
     * @return location of hypertext directory either as relative path, absolute
     * file path, or jar resource path
     */
    public String getHypertextUrl() {
        return configuration.get(JETTY_HYPERTEXT, path("kms-html5/src/main/resources/www"));
    }

    /**
     * Default is used during development so you can run "kms start" from
     * the dcg_security-kms source directory.
     *
     * @return location of web.xml either as relative path, absolute file path,
     * or absolute URL
     */
    public String getDescriptorUrl() {
        return configuration.get(JETTY_WEBXML, path("kms-servlet3/src/main/resources/WEB-INF/web.xml"));
    }

    /*
     * Environment variables:
     * JETTY_HYPERTEXT should be relative or absolute path to the hypertext folder containing index.html and related resources
     * JETTY_WEBXML should be relative or absolute path to the web.xml file 
     * JETTY_HTTP_PORT should be the port number on which jetty should listen for insecure connections
     * JETTY_HTTPS_PORT should be the port number on which jetty should listen for secure connections
     * 
     * Defaults are relative paths from the project's source directory, for convenience during development.
     * Default ports are 80,443
     * 
     * Example of Windows relative paths to files in a JAR:
     * set JETTY_HYPERTEXT=jar:file:./kms-jetty9-0.1-SNAPSHOT.jar!/hypertext
     * set JETTY_WEBXML=jar:file:./kms-jetty9-0.1-SNAPSHOT.jar!/WEB-INF/web.xml
     * 
     * Example of Windows absolute path to files in a JAR:
     * set JETTY_HYPERTEXT=jar:file:///C:/Users/username/kms/kms-jetty9-0.1-SNAPSHOT.jar!/hypertext
     * set JETTY_WEBXML=jar:file:///C:/Users/username/kms/kms-jetty9-0.1-SNAPSHOT.jar!/WEB-INF/web.xml
     * 
     * Example of Linux relative paths to files in a JAR:
     * export JETTY_HYPERTEXT=jar:file:./kms-jetty9-0.1-SNAPSHOT.jar!/hypertext
     * export JETTY_WEBXML=jar:file:./kms-jetty9-0.1-SNAPSHOT.jar!/WEB-INF/web.xml
     * 
     * Example of Linux absolute paths to files in a JAR:
     * export JETTY_HYPERTEXT=jar:file:///opt/kms/java/kms-jetty9-0.1-SNAPSHOT.jar!/hypertext
     * export JETTY_WEBXML=jar:file:///opt/kms/java/kms-jetty9-0.1-SNAPSHOT.jar!/WEB-INF/web.xml
     * 
     * See also: http://wiki.eclipse.org/Jetty/Tutorial/Embedding_Jetty
     */
    public void startJettyHttpServer() {
        // default configuration allows running "java -jar artifact-with-dependencies.jar" from maven project directory
        // in production, set the variables to point to the installed resources
        String resourceBase = getHypertextUrl();
        String descriptor = getDescriptorUrl();

        log.debug("{}={}", JETTY_HYPERTEXT, resourceBase);
        log.debug("{}={}", JETTY_WEBXML, descriptor);

        WebAppContext webapp = new WebAppContext();
        webapp.setContextPath("/");
        webapp.setResourceBase(resourceBase);
        webapp.setDescriptor(descriptor); // can also be relative to jar like WEB-INF\\web.xml
        webapp.setDefaultsDescriptor(null); // turn off jsp support
        webapp.setParentLoaderPriority(true);

        // common configuration for http/https
        HttpConfiguration httpConfiguration = new HttpConfiguration();
        httpConfiguration.setSecureScheme("https");
        httpConfiguration.setSecurePort(getHttpsPort());
        httpConfiguration.setOutputBufferSize(32768);
        httpConfiguration.setRequestHeaderSize(8192);
        httpConfiguration.setResponseHeaderSize(8192);

        // https-specific configuration
        HttpConfiguration httpsConfiguration = new HttpConfiguration(httpConfiguration);
        httpsConfiguration.addCustomizer(new SecureRequestCustomizer()); // adds ssl session id's and certificate information to request attributes

        // http connector
        ServerConnector http = new ServerConnector(jetty, new ConnectionFactory[]{new HttpConnectionFactory(httpConfiguration)});
        http.setPort(getHttpPort());
        log.debug("{}={}", Jetty.JETTY_PORT, http.getPort());

        // https connector
        try {
        SslContextFactory sslConnectionFactory = new SslContextFactory();
        sslConnectionFactory.setKeyStorePath(getKeystoreFile().getAbsolutePath());
        Password keystorePassword = getKeystorePassword();
        if( keystorePassword != null ) {
        sslConnectionFactory.setKeyStorePassword(new String(getKeystorePassword().toCharArray()));
        }
        sslConnectionFactory.setIncludeProtocols("TLSv1", "TLSv1.1", "TLSv1.2");
        ServerConnector https = new ServerConnector(jetty, new ConnectionFactory[]{new SslConnectionFactory(sslConnectionFactory, "http/1.1"), new HttpConnectionFactory(httpsConfiguration)});
        https.setPort(getHttpsPort());
        log.debug("{}={}", Jetty.JETTY_SECURE_PORT, https.getPort());

        jetty.setConnectors(new Connector[]{http, https});
        jetty.setHandler(webapp);

            jetty.start();
            log.info("Started HTTP service: {}", jetty.getURI().toURL().toExternalForm());
        } catch (Exception e) {
            log.error("Error while starting jetty", e);
        }
    }

    public void blockUntilHttpServerShutdown() {
        try {
            if (jetty.isRunning()) {
                jetty.join();
            }
        } catch (Exception e) {
            log.error("Error while running jetty", e);
        } finally {
            try {
                jetty.stop();
            } catch (Exception e) {
                log.error("Error while stopping jetty", e);
            }
        }
    }
}
