package com.pingan.b2bic.Util;

/*
 * $Header: /ibcvsrep/cn.com.pingan.b2bic/src/cn/com/pingan/b2bic/http/AuthSSLProtocolSocketFactory.java,v 1.1 2014/10/27 08:05:43 guolt Exp $
 * $Revision: 1.1 $
 * $Date: 2014/10/27 08:05:43 $
 *
 * ====================================================================
 *
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation.  For more
 * information on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 *
 */

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.SecureProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.net.SocketFactory;
import javax.net.ssl.*;

import java.io.IOException;
import java.io.InputStream;
import java.net.*;
import java.net.UnknownHostException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 * <p>
 * AuthSSLProtocolSocketFactory can be used to validate the identity of the HTTPS
 * server against a list of trusted certificates and to authenticate to the HTTPS
 * server using a private key.
 * </p>
 *
 * <p>
 * AuthSSLProtocolSocketFactory will enable server authentication when supplied with
 * a {@link KeyStore truststore} file containg one or several trusted certificates.
 * The client secure socket will reject the connection during the SSL session handshake
 * if the target HTTPS server attempts to authenticate itself with a non-trusted
 * certificate.
 * </p>
 *
 * <p>
 * Use JDK keytool utility to import a trusted certificate and generate a truststore file:
 *    <pre>
 *     keytool -import -alias "my server cert" -file server.crt -keystore my.truststore
 *    </pre>
 * </p>
 *
 * <p>
 * AuthSSLProtocolSocketFactory will enable client authentication when supplied with
 * a {@link KeyStore keystore} file containg a private key/public certificate pair.
 * The client secure socket will use the private key to authenticate itself to the target
 * HTTPS server during the SSL session handshake if requested to do so by the server.
 * The target HTTPS server will in its turn verify the certificate presented by the client
 * in order to establish client's authenticity
 * </p>
 *
 * <p>
 * Use the following sequence of actions to generate a keystore file
 * </p>
 *   <ul>
 *     <li>
 *      <p>
 *      Use JDK keytool utility to generate a new key
 *      <pre>keytool -genkey -v -alias "my client key" -validity 365 -keystore my.keystore</pre>
 *      For simplicity use the same password for the key as that of the keystore
 *      </p>
 *     </li>
 *     <li>
 *      <p>
 *      Issue a certificate signing request (CSR)
 *      <pre>keytool -certreq -alias "my client key" -file mycertreq.csr -keystore my.keystore</pre>
 *     </p>
 *     </li>
 *     <li>
 *      <p>
 *      Send the certificate request to the trusted Certificate Authority for signature.
 *      One may choose to act as her own CA and sign the certificate request using a PKI
 *      tool, such as OpenSSL.
 *      </p>
 *     </li>
 *     <li>
 *      <p>
 *       Import the trusted CA root certificate
 *       <pre>keytool -import -alias "my trusted ca" -file caroot.crt -keystore my.keystore</pre>
 *      </p>
 *     </li>
 *     <li>
 *      <p>
 *       Import the PKCS#7 file containg the complete certificate chain
 *       <pre>keytool -import -alias "my client key" -file mycert.p7 -keystore my.keystore</pre>
 *      </p>
 *     </li>
 *     <li>
 *      <p>
 *       Verify the content the resultant keystore file
 *       <pre>keytool -list -v -keystore my.keystore</pre>
 *      </p>
 *     </li>
 *   </ul>
 * <p>
 * Example of using custom protocol socket factory for a specific host:
 *     <pre>
 *     Protocol authhttps = new Protocol("https",
 *          new AuthSSLProtocolSocketFactory(
 *              new URL("file:my.keystore"), "mypassword",
 *              new URL("file:my.truststore"), "mypassword"), 443);
 *
 *     HttpClient client = new HttpClient();
 *     client.getHostConfiguration().setHost("localhost", 443, authhttps);
 *     // use relative url only
 *     GetMethod httpget = new GetMethod("/");
 *     client.executeMethod(httpget);
 *     </pre>
 * </p>
 * <p>
 * Example of using custom protocol socket factory per default instead of the standard one:
 *     <pre>
 *     Protocol authhttps = new Protocol("https",
 *          new AuthSSLProtocolSocketFactory(
 *              new URL("file:my.keystore"), "mypassword",
 *              new URL("file:my.truststore"), "mypassword"), 443);
 *     Protocol.registerProtocol("https", authhttps);
 *
 *     HttpClient client = new HttpClient();
 *     GetMethod httpget = new GetMethod("https://localhost/");
 *     client.executeMethod(httpget);
 *     </pre>
 * </p>
 * @author <a href="mailto:oleg -at- ural.ru">Oleg Kalnichevski</a>
 *
 * <p>
 * DISCLAIMER: HttpClient developers DO NOT actively support this component.
 * The component is provided as a reference material, which may be inappropriate
 * for use without additional customization.
 * </p>
 */


/**
 * 修改org.apache.commons.httpclient.contrib.ssl.AuthSSLProtocolSocketFactory，支持指定证书库类型
 *
 * @author ywb date: 20130727
 */
public class AuthSSLProtocolSocketFactory implements SecureProtocolSocketFactory {

    /** Log object for this class. */
    private static final Log LOG = LogFactory.getLog(AuthSSLProtocolSocketFactory.class);

    private URL keystoreUrl = null;
    private String keystorePassword = null;
    private URL truststoreUrl = null;
    private String truststorePassword = null;
    private SSLContext sslcontext = null;

    /** 证书库类型 */
    private String keyStoreType;
    private String trustKeyStoreType;
    private boolean authSrv = false;
    /** SSL算法 */
    private String sslAlgorithm = "SSL";

    /**
     * Constructor for AuthSSLProtocolSocketFactory. Either a keystore or truststore file
     * must be given. Otherwise SSL context initialization error will result.
     *
     * @param keystoreUrl URL of the keystore file. May be <tt>null</tt> if HTTPS client
     *        authentication is not to be used.
     * @param keystorePassword Password to unlock the keystore. IMPORTANT: this implementation
     *        assumes that the same password is used to protect the key and the keystore itself.
     * @param truststoreUrl URL of the truststore file. May be <tt>null</tt> if HTTPS server
     *        authentication is not to be used.
     * @param truststorePassword Password to unlock the truststore.
     */
    public AuthSSLProtocolSocketFactory(
            final URL keystoreUrl, final String keystorePassword,
            final URL truststoreUrl, final String truststorePassword)
    {
        super();
        this.keystoreUrl = keystoreUrl;
        this.keystorePassword = keystorePassword;
        this.truststoreUrl = truststoreUrl;
        this.truststorePassword = truststorePassword;
    }

    private static KeyStore createKeyStore(final URL url, final String password, String keyStoreType)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException
    {
        if (url == null) {
            throw new IllegalArgumentException("Keystore url may not be null");
        }
        LOG.debug("Initializing key store");
        if (keyStoreType == null || keyStoreType.length() == 0) {
            keyStoreType = KeyStore.getDefaultType();
        }
        KeyStore keystore  = KeyStore.getInstance(keyStoreType);

        InputStream is = null;
        try {
            is = url.openStream();
            keystore.load(is, password != null ? password.toCharArray(): null);
        } finally {
            if (is != null) is.close();
        }
        return keystore;
    }

    private static KeyManager[] createKeyManagers(final KeyStore keystore, final String password)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException
    {
        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        }
        LOG.debug("Initializing key manager");
        KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmfactory.init(keystore, password != null ? password.toCharArray(): null);
        return kmfactory.getKeyManagers();
    }

    private static TrustManager[] createTrustManagers(final KeyStore keystore)
            throws KeyStoreException, NoSuchAlgorithmException
    {
        if (keystore == null) {
            throw new IllegalArgumentException("Keystore may not be null");
        }
        LOG.debug("Initializing trust manager");
        TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
        tmfactory.init(keystore);
        TrustManager[] trustmanagers = tmfactory.getTrustManagers();
//        for (int i = 0; i < trustmanagers.length; i++) {
//            if (trustmanagers[i] instanceof X509TrustManager) {
//                trustmanagers[i] = new AuthSSLX509TrustManager(
//                    (X509TrustManager)trustmanagers[i]);
//            }
//        }
        return trustmanagers;
    }

    private SSLContext createSSLContext() {
        try {
            KeyManager[] keymanagers = null;
            TrustManager[] trustmanagers = null;
            if (this.keystoreUrl != null) {
                KeyStore keystore = createKeyStore(this.keystoreUrl, this.keystorePassword, keyStoreType);
                if (LOG.isDebugEnabled()) {
                    Enumeration aliases = keystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = (String)aliases.nextElement();
                        Certificate[] certs = keystore.getCertificateChain(alias);
                        if (certs != null) {
                            LOG.debug("Certificate chain '" + alias + "':");
                            for (int c = 0; c < certs.length; c++) {
                                if (certs[c] instanceof X509Certificate) {
                                    X509Certificate cert = (X509Certificate)certs[c];
                                    LOG.debug(" Certificate " + (c + 1) + ":");
                                    LOG.debug("  Subject DN: " + cert.getSubjectDN());
                                    LOG.debug("  Signature Algorithm: " + cert.getSigAlgName());
                                    LOG.debug("  Valid from: " + cert.getNotBefore() );
                                    LOG.debug("  Valid until: " + cert.getNotAfter());
                                    LOG.debug("  Issuer: " + cert.getIssuerDN());
                                }
                            }
                        }
                    }
                }
                keymanagers = createKeyManagers(keystore, this.keystorePassword);
            }
            if ( authSrv && this.truststoreUrl != null ) {
                KeyStore keystore = createKeyStore(this.truststoreUrl, this.truststorePassword, trustKeyStoreType);
                if (LOG.isDebugEnabled()) {
                    Enumeration aliases = keystore.aliases();
                    while (aliases.hasMoreElements()) {
                        String alias = (String)aliases.nextElement();
                        LOG.debug("Trusted certificate '" + alias + "':");
                        Certificate trustedcert = keystore.getCertificate(alias);
                        if (trustedcert != null && trustedcert instanceof X509Certificate) {
                            X509Certificate cert = (X509Certificate)trustedcert;
                            LOG.debug("  Subject DN: " + cert.getSubjectDN());
                            LOG.debug("  Signature Algorithm: " + cert.getSigAlgName());
                            LOG.debug("  Valid from: " + cert.getNotBefore() );
                            LOG.debug("  Valid until: " + cert.getNotAfter());
                            LOG.debug("  Issuer: " + cert.getIssuerDN());
                        }
                    }
                }
                trustmanagers = createTrustManagers(keystore);
            } else if (!authSrv) {
                trustmanagers = new TrustManager[] {
                        new X509TrustManager() {
                            public void checkClientTrusted(X509Certificate[] arg0,
                                                           String arg1) throws CertificateException {
                            }

                            public void checkServerTrusted(X509Certificate[] arg0,
                                                           String arg1) throws CertificateException {
                            }

                            public X509Certificate[] getAcceptedIssuers() {
                                return new X509Certificate[0];
                            }
                        }
                };
            }
            SSLContext sslcontext = SSLContext.getInstance(sslAlgorithm);
            sslcontext.init(keymanagers, trustmanagers, null);
            return sslcontext;
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            throw new RuntimeException(e);
        }
    }

    private SSLContext getSSLContext() {
        if (this.sslcontext == null) {
            this.sslcontext = createSSLContext();
        }
        return this.sslcontext;
    }

    /**
     * Attempts to get a new socket connection to the given host within the given time limit.
     * <p>
     * To circumvent the limitations of older JREs that do not support connect timeout a
     * controller thread is executed. The controller thread attempts to create a new socket
     * within the given limit of time. If socket constructor does not return until the
     * timeout expires, the controller terminates and throws an {@link ConnectTimeoutException}
     * </p>
     *
     * @param host the host name/IP
     * @param port the port on the host
     * @param clientHost the local host name/IP to bind the socket to
     * @param clientPort the port on the local machine
     * @param params {@link HttpConnectionParams Http connection parameters}
     *
     * @return Socket a new socket
     *
     * @throws IOException if an I/O error occurs while creating the socket
     * @throws UnknownHostException if the IP address of the host cannot be
     * determined
     */
    public Socket createSocket(
            final String host,
            final int port,
            final InetAddress localAddress,
            final int localPort,
            final HttpConnectionParams params
    ) throws IOException {
        if (params == null) {
            throw new IllegalArgumentException("Parameters may not be null");
        }
        int timeout = params.getConnectionTimeout();
        SocketFactory socketfactory = getSSLContext().getSocketFactory();
        if (timeout == 0) {
            return socketfactory.createSocket(host, port, localAddress, localPort);
        } else {
            Socket socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, timeout);
            return socket;
        }
    }

    public Socket createSocket(
            final String host,
            final int port,
            final InetAddress localAddress,
            final int localPort,
            final int connectTimeout
    ) throws IOException {
        SocketFactory socketfactory = getSSLContext().getSocketFactory();
        if (connectTimeout == 0) {
            return socketfactory.createSocket(host, port, localAddress, localPort);
        } else {
            Socket socket = socketfactory.createSocket();
            SocketAddress localaddr = new InetSocketAddress(localAddress, localPort);
            SocketAddress remoteaddr = new InetSocketAddress(host, port);
            socket.bind(localaddr);
            socket.connect(remoteaddr, connectTimeout);
            return socket;
        }
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int,java.net.InetAddress,int)
     */
    public Socket createSocket(
            String host,
            int port,
            InetAddress clientHost,
            int clientPort)
            throws IOException {
        return getSSLContext().getSocketFactory().createSocket(
                host,
                port,
                clientHost,
                clientPort
        );
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.lang.String,int)
     */
    public Socket createSocket(String host, int port)
            throws IOException {
        return getSSLContext().getSocketFactory().createSocket(
                host,
                port
        );
    }

    /**
     * @see SecureProtocolSocketFactory#createSocket(java.net.Socket,java.lang.String,int,boolean)
     */
    public Socket createSocket(
            Socket socket,
            String host,
            int port,
            boolean autoClose)
            throws IOException {
        return getSSLContext().getSocketFactory().createSocket(
                socket,
                host,
                port,
                autoClose
        );
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getTrustKeyStoreType() {
        return trustKeyStoreType;
    }

    public void setTrustKeyStoreType(String trustKeyStoreType) {
        this.trustKeyStoreType = trustKeyStoreType;
    }

    public String getSslAlgorithm() {
        return sslAlgorithm;
    }

    public void setSslAlgorithm(String sslAlgorithm) {
        this.sslAlgorithm = sslAlgorithm;
    }

    public boolean isAuthSrv()
    {
        return authSrv;
    }

    public void setAuthSrv(boolean authSrv)
    {
        this.authSrv = authSrv;
    }


}

