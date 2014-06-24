/*
 * X509CertificateServer.java
 *
 * Created on May 14, 2010, 12:21:54 PM
 *
 * Description: Provides an X.509 certificate-issuing web service.
 *
 * Copyright (C) May 14, 2010, Stephen L. Reed.
 *
 * This program is free software; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program;
 * if not, write to the Free Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
package org.texai.x509certificateserver;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import net.jcip.annotations.ThreadSafe;
import net.sbbi.upnp.impls.InternetGatewayDevice;
import net.sbbi.upnp.messages.ActionResponse;
import net.sbbi.upnp.messages.UPNPResponseException;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelException;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.websocketx.TextWebSocketFrame;
import org.texai.network.netty.handler.AbstractHTTPRequestHandlerFactory;
import org.texai.network.netty.handler.HTTPRequestHandler;
import org.texai.network.netty.handler.HTTPRequestHandlerFactory;
import org.texai.network.netty.handler.TexaiHTTPRequestHandler;
import org.texai.network.netty.pipeline.PortUnificationChannelPipelineFactory;
import org.texai.network.netty.pipeline.SSLPipelineFactory;
import org.texai.network.netty.utils.NettyHTTPUtils;
import org.texai.util.Base64Coder;
import org.texai.util.ByteUtils;
import org.texai.util.NetworkUtils;
import org.texai.util.StringUtils;
import org.texai.util.TexaiException;
import org.texai.x509.X509SecurityInfo;
import org.texai.x509.X509Utils;

/** Provides an X.509 certificate-issuing web service.
 *
 * @author reed
 */
@ThreadSafe
public class X509CertificateServer implements TexaiHTTPRequestHandler {

  /** the logger */
  private static final Logger LOGGER = Logger.getLogger(X509CertificateServer.class);
  /** the indicator whether debug logging is enabled */
  private static final boolean IS_DEBUG_LOGGING_ENABLED = LOGGER.isDebugEnabled();
  /** the issuer's private key */
  private static PrivateKey issuerPrivateKey;
  /** the issuer's certificate */
  private static X509Certificate issuerCertificate;
  /** the issuer's certificate chain, in which the first certificate is the issuer's certificate */
  private static List<Certificate> issuersCertificateChain;
  /** the number certificates served */
  private final AtomicInteger nbrCertificatesServed = new AtomicInteger(0);
  /** the certificate generation duration milliseconds */
  private final AtomicLong certificateGenerationDurationMillis = new AtomicLong(0L);
  /** the UPNP discovery timeout of 5 seconds */
  private static final int UPNP_DISCOVERY_TIMEOUT = 3000;
//  static {
//    System.setProperty("javax.net.debug", "all");
//  }

  /** Constructs a new X509CertificateServer instance. */
  public X509CertificateServer() {
    //Preconditions
    // in this preliminary version of the server, the issuer certificate is the root certificate
    assert X509Utils.isTrustedDevelopmentSystem();

    initialize();
  }

  /** Initializes the root X.509 security information. */
  private static synchronized void initialize() {
    issuerPrivateKey = X509Utils.getRootPrivateKey();
    issuerCertificate = X509Utils.getRootX509Certificate();
    issuersCertificateChain = new ArrayList<>();
  }

  /** Handles the HTTP request.
   *
   * @param httpRequest the HTTP request
   * @param channel the channel
   * @return the indicator whether the HTTP request was handled
   */
  @Override
  public boolean httpRequestReceived(final HttpRequest httpRequest, final Channel channel) {
    //Preconditions
    assert httpRequest != null : "httpRequest must not be null";
    assert channel != null : "channel must not be null";

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("httpRequest: " + httpRequest);
      LOGGER.debug("method: " + httpRequest.getMethod());
      LOGGER.debug("protocol version: " + httpRequest.getProtocolVersion());
      LOGGER.debug("uri: " + httpRequest.getUri());
      for (final String headerName : httpRequest.getHeaderNames()) {
        LOGGER.debug("header: " + headerName + " " + httpRequest.getHeader(headerName));
      }
    }
    final URI uri;
    try {
      uri = new URI(httpRequest.getUri());
    } catch (URISyntaxException ex) {
      throw new TexaiException(ex);
    }
    final String path = uri.getPath();
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug(Thread.currentThread().getName() + " path: " + path);
      LOGGER.debug(Thread.currentThread().getName() + " User-Agent: " + httpRequest.getHeader("User-Agent"));
      LOGGER.debug(httpRequest.getMethod() + " " + path);
    }

    if (httpRequest.getMethod().equals(HttpMethod.POST) && path.equals("/CA/certificate-request")) {
      // X.509 certificate request
      if (IS_DEBUG_LOGGING_ENABLED) {
        LOGGER.debug("request: " + httpRequest);
      }
      final byte[] base64SerializedClientPublicKeyBytes = httpRequest.getContent().array();
      if (base64SerializedClientPublicKeyBytes.length == 0) {
        NettyHTTPUtils.writeHTMLResponse(
                httpRequest,
                "<html><body><h2>Certificate request is missing its content.</h2></body></html>",
                channel,
                null); // sessionCookie
        return true;
      }
      final String base64SerializedClientPublicKey = new String(base64SerializedClientPublicKeyBytes);
      if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("base64SerializedClientPublicKeyBytes: " + base64SerializedClientPublicKey);
      }
      final byte[] publicKeyBytes = Base64Coder.decode(base64SerializedClientPublicKey);
      final PublicKey myPublicKey = (PublicKey) ByteUtils.deserialize(publicKeyBytes);
      try {
        final long startTimeMillis = System.currentTimeMillis();
        final X509Certificate x509Certificate = X509Utils.generateIntermediateX509Certificate(
                myPublicKey,
                issuerPrivateKey,
                issuerCertificate,
                0);  // pathLengthConstraint
        final List<Certificate> certificateList = new ArrayList<>();
        certificateList.add(x509Certificate);
        certificateList.addAll(issuersCertificateChain);
        final CertPath certPath = X509Utils.generateCertPath(certificateList);
        X509Utils.validateCertificatePath(certPath);
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("certPath bytes length: " + ByteUtils.serialize(certPath).length);
        }
        NettyHTTPUtils.writeBinaryResponse(
                httpRequest,
                ByteUtils.serialize(certPath),
                channel,
                null); // sessionCookie
        nbrCertificatesServed.getAndIncrement();
        certificateGenerationDurationMillis.addAndGet(System.currentTimeMillis() - startTimeMillis);
        LOGGER.info("served X.509 certificate " + nbrCertificatesServed.toString() + " to: " + channel.getRemoteAddress());
      } catch (final NoSuchProviderException | NoSuchAlgorithmException | SignatureException | InvalidKeyException | IOException | CertificateException | InvalidAlgorithmParameterException | CertPathValidatorException ex) {
        LOGGER.error("exception message: " + ex.getMessage());
        LOGGER.error("exception: " + ex);
        LOGGER.error(StringUtils.getStackTraceAsString(ex));
        NettyHTTPUtils.writeHTMLResponse(
                httpRequest,
                "<html><body><h2>An error occured.</h2></body></html>",
                channel,
                null); // sessionCookie
      }
    } else {
      NettyHTTPUtils.writeHTMLResponse(
              httpRequest,
              "<html><body><h2>Invalid certificate request.</h2></body></html>",
                channel,
                null); // sessionCookie
    }
    return true;
  }

  /** Gets the number certificates served.
   *
   * @return the number certificates served
   */
  public int getNbrCertificatesServed() {
    return nbrCertificatesServed.get();
  }

  /** Gets the certificate generation duration milliseconds.
   *
   * @return the certificate generation duration milliseconds
   */
  public long getCertificateGenerationDurationMillis() {
    return certificateGenerationDurationMillis.get();
  }

  /** Uses Universal Plug and Play to configure the NAT router to forward port 443 to this host.
   *
   * @return whether mapping succeeded
   */
  private static boolean configureSSLServerPortForwarding() {
    LOGGER.info("configuring the NAT to forward port 443 to the message router");
    try {
      final InternetGatewayDevice[] internetGatewayDevices = InternetGatewayDevice.getDevices(UPNP_DISCOVERY_TIMEOUT);
      if (internetGatewayDevices == null) {
        LOGGER.info("no UPnP router found");
        return true;
      } else {
        // let's use the the first device found
        final InternetGatewayDevice internetGatewayDevice = internetGatewayDevices[0];
        LOGGER.info("Found device " + internetGatewayDevice.getIGDRootDevice().getModelDescription());
        // now let's open the port
        final InetAddress localHostAddress = NetworkUtils.getLocalHostAddress();
        LOGGER.info("local host address: " + localHostAddress.getHostAddress());
        // we assume that localHostIP is something else than 127.0.0.1
        final boolean isMapped = internetGatewayDevice.addPortMapping(
                "Texai SSL message router", // description
                null, // remote host
                NetworkUtils.getDynamicServerPort(), // internal port
                443, // external port
                localHostAddress.getHostAddress(),
                0, // lease duration in seconds, 0 for an infinite time
                "TCP");  // protocol
        if (isMapped) {
          LOGGER.info("Port 443 mapped to " + localHostAddress.getHostAddress());

          final ActionResponse actionResponse = internetGatewayDevice.getSpecificPortMappingEntry(
                  null, // remoteHost
                  443, // external port
                  "TCP");  // protocol
          LOGGER.info("mapping info:\n" + actionResponse);

          // eventually revert the port mapping when the JVM is shutdown
          final ShutdownRunnable shutdownRunnable = new ShutdownRunnable(internetGatewayDevice);
          Runtime.getRuntime().addShutdownHook(new Thread(shutdownRunnable));
        } else {
          LOGGER.info("Port 443 cannot be mapped at " + internetGatewayDevice.getIGDRootDevice().getModelDescription());
          return false;
        }
      }
    } catch (IOException | UPNPResponseException ex) {
      throw new TexaiException(ex);
    }
    try {
      // wait for discovery listener thread to finish
      Thread.sleep(1000);
    } catch (InterruptedException ex) {
      throw new TexaiException(ex);
    }
    return true;
  }

  /** Handles a received text web socket frame.
   *
   * @param channel the channel handler context
   * @param textWebSocketFrame  the text web socket frame
   * @return the indicator whether the web socket request was handled
   */
  @Override
  public boolean textWebSocketFrameReceived(
          final Channel channel,
          final TextWebSocketFrame textWebSocketFrame) {
    throw new UnsupportedOperationException("Not supported yet.");
  }

  /** Provides a JVM shutdown task that releases resources held by this application. */
  static final class ShutdownRunnable implements Runnable {

    /** the internet gateway device - NAT */
    private final InternetGatewayDevice internetGatewayDevice;

    /** Constructs a new ShutdownRunnable instance.
     *
     * @param internetGatewayDevice the internet gateway device - NAT
     */
    ShutdownRunnable(final InternetGatewayDevice internetGatewayDevice) {
      //Preconditions
      assert internetGatewayDevice != null : "internetGatewayDevice must not be null";

      this.internetGatewayDevice = internetGatewayDevice;
    }

    /** Releases resources held by this application when the containing JVM shuts down. */
    @Override
    public void run() {
      LOGGER.info("releasing resources held by the message router");
      // removes NAT mapping
      try {
        final boolean isUnmapped = internetGatewayDevice.deletePortMapping(null, 443, "TCP");
        if (isUnmapped) {
          LOGGER.info("Port 443 unmapped");
        }
      } catch (IOException | UPNPResponseException ex) {
        throw new TexaiException(ex);
      }
    }
  }

  /** Executes this application.
   *
   * @param args the command-line arguments (unused)
   */
  @SuppressWarnings("ThrowableResultIgnored")
  public static void main(final String[] args) {
    configureSSLServerPortForwarding();
    Logger.getLogger(PortUnificationChannelPipelineFactory.class).setLevel(Level.WARN);
    Logger.getLogger(SSLPipelineFactory.class).setLevel(Level.WARN);
    final X509CertificateServer x509CertificateServer = new X509CertificateServer();
    LOGGER.info("CA certificate: " + issuerCertificate.getSubjectX500Principal().toString());

    // configure the HTTP request handler by registering the X.509 certificate server
    final HTTPRequestHandler httpRequestHandler = HTTPRequestHandler.getInstance();
    httpRequestHandler.register(x509CertificateServer);

    // configure the server channel pipeline factory
    final AbstractHTTPRequestHandlerFactory httpRequestHandlerFactory = new HTTPRequestHandlerFactory();
    LOGGER.info("generating SSL certificate");
    final KeyPair keyPair;
    try {
      keyPair = X509Utils.generateRSAKeyPair2048();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      throw new TexaiException(ex);
    }
    final char[] keystorePassword = "server ssl keystore password".toCharArray();
    final X509SecurityInfo x509SecurityInfo = X509Utils.generateX509SecurityInfo(
            keyPair,
            issuerPrivateKey,
            issuerCertificate,
            UUID.randomUUID(), // uid
            keystorePassword,
            X509Utils.isJCEUnlimitedStrengthPolicy(),
            null); // domainComponent
    final ChannelPipelineFactory channelPipelineFactory = new PortUnificationChannelPipelineFactory(
            null, // albusHCNMessageHandlerFactory,
            null, // bitTorrentHandlerFactory,
            httpRequestHandlerFactory,
            x509SecurityInfo);

    // configure the server
    final ServerBootstrap serverBootstrap = new ServerBootstrap(new NioServerSocketChannelFactory(
            Executors.newCachedThreadPool(),
            Executors.newCachedThreadPool()));

    serverBootstrap.setPipelineFactory(channelPipelineFactory);

    // bind and start to accept incoming connections
    final SocketAddress localAddress = new InetSocketAddress(443);
    try {
      serverBootstrap.bind(localAddress);
    } catch (Throwable ex) {
      if (ex.getCause() instanceof ChannelException) {
        final ChannelException channelException = (ChannelException) ex.getCause();
        if (channelException.getCause().toString().equals("Permission denied")) {
          LOGGER.error("must run the X.509 certificate server as root to serve from port 443");
          System.exit(1);
        }
      }
    }
    LOGGER.info("serving X.509 certificates from: " + localAddress);
  }
}
