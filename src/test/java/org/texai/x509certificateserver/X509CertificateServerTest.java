/*
 * X509CertificateServerTest.java
 *
 * Created on May 14, 2010, 3:32:25 PM
 *
 * Description: .
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

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Timer;
import java.util.TimerTask;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import org.jboss.netty.bootstrap.ClientBootstrap;
import org.jboss.netty.bootstrap.ServerBootstrap;
import org.jboss.netty.buffer.ChannelBuffer;
import org.jboss.netty.buffer.ChannelBuffers;
import org.jboss.netty.channel.Channel;
import org.jboss.netty.channel.ChannelFuture;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.codec.http.DefaultHttpRequest;
import org.jboss.netty.handler.codec.http.HttpHeaders;
import org.jboss.netty.handler.codec.http.HttpMethod;
import org.jboss.netty.handler.codec.http.HttpRequest;
import org.jboss.netty.handler.codec.http.HttpVersion;
import org.junit.After;
import org.junit.AfterClass;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.texai.network.netty.handler.AbstractHTTPRequestHandlerFactory;
import org.texai.network.netty.handler.AbstractHTTPResponseHandler;
import org.texai.network.netty.handler.HTTPRequestHandler;
import org.texai.network.netty.handler.HTTPRequestHandlerFactory;
import org.texai.network.netty.handler.PortUnificationHandler;
import org.texai.network.netty.pipeline.HTTPClientPipelineFactory;
import org.texai.network.netty.pipeline.PortUnificationChannelPipelineFactory;
import org.texai.network.netty.pipeline.SSLPipelineFactory;
import org.texai.ssl.TexaiSSLContextFactory;
import org.texai.util.Base64Coder;
import org.texai.util.ByteUtils;
import org.texai.util.StringUtils;
import org.texai.util.TexaiException;
import org.texai.x509.KeyStoreTestUtils;
import org.texai.x509.X509SecurityInfo;
import org.texai.x509.X509Utils;

/**
 *
 * @author reed
 */
public class X509CertificateServerTest {

  /** the logger */
  private static final Logger LOGGER = Logger.getLogger(X509CertificateServerTest.class);
  /** the server port */
  private static final int SERVER_PORT = 8088;
  /** the number certificates served */
  private final AtomicInteger nbrKeyPairsGenerated = new AtomicInteger(0);
  /** the certificate generation duration milliseconds */
  private final AtomicLong keyPairGenerationDurationMillis = new AtomicLong(0L);
//  static {
//    System.setProperty("javax.net.debug", "all");
//  }

  /** Constructs a new X509CertificateServerTest instance. */
  public X509CertificateServerTest() {
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
    /** sets debugging */
  }

  @AfterClass
  public static void tearDownClass() throws Exception {
  }

  @Before
  public void setUp() {
  }

  @After
  public void tearDown() {
  }

  /**
   * Test of class ChatServer.
   */
  @Test
  public void testX509CertificateServer() {
    LOGGER.info("testX509CertificateServer");
    Logger.getLogger(PortUnificationHandler.class).setLevel(Level.WARN);
    Logger.getLogger(PortUnificationChannelPipelineFactory.class).setLevel(Level.WARN);

    Logger.getLogger(HTTPRequestHandler.class).setLevel(Level.WARN);
    Logger.getLogger(TexaiSSLContextFactory.class).setLevel(Level.WARN);
    Logger.getLogger(SSLPipelineFactory.class).setLevel(Level.WARN);
    Logger.getLogger(HTTPClientPipelineFactory.class).setLevel(Level.WARN);

    if (!X509Utils.isTrustedDevelopmentSystem()) {
      LOGGER.info("bypassing the X509CertificateServer test when it is not run on the trusted development system");
      return;
    }
    final X509CertificateServer x509CertificateServer = new X509CertificateServer();

    // configure the HTTP request handler by registering the X.509 certificate server
    final HTTPRequestHandler httpRequestHandler = HTTPRequestHandler.getInstance();
    httpRequestHandler.register(x509CertificateServer);

    // configure the server channel pipeline factory
    final AbstractHTTPRequestHandlerFactory httpRequestHandlerFactory = new HTTPRequestHandlerFactory();
    final X509SecurityInfo x509SecurityInfo = KeyStoreTestUtils.getServerX509SecurityInfo();
    final ChannelPipelineFactory channelPipelineFactory = new PortUnificationChannelPipelineFactory(
            null, // albusHCNMessageHandlerFactory,
            null, // bitTorrentHandlerFactory,
            httpRequestHandlerFactory,
            x509SecurityInfo);

    // configure the server
    final ServerBootstrap serverBootstrap = new ServerBootstrap(new NioServerSocketChannelFactory(
            Executors.newCachedThreadPool(),
            Executors.newCachedThreadPool()));

    assertEquals("{}", serverBootstrap.getOptions().toString());
    serverBootstrap.setPipelineFactory(channelPipelineFactory);

    try {
      // bind and start to accept incoming connections
      final SocketAddress socketAddress = new InetSocketAddress(InetAddress.getByName("localhost"), SERVER_PORT);
      LOGGER.info("binding server to " + socketAddress);
      serverBootstrap.bind(socketAddress);
    } catch (UnknownHostException ex) {
      throw new TexaiException(ex);
    }

    // test chat server with mock clients
    //final int nbrThreads = 2;
    final int nbrThreads = Runtime.getRuntime().availableProcessors();
    LOGGER.info("launching " + nbrThreads + " test threads");
    final CountDownLatch countDownLatch = new CountDownLatch(nbrThreads);
    for (int i = 0; i < nbrThreads; i++) {
      final MockHTTPClientTask mockHTTPClientTask = new MockHTTPClientTask(countDownLatch, i + 1);
      new Thread(mockHTTPClientTask).start();
    }

    try {
      countDownLatch.await();
    } catch (InterruptedException ex) {
      LOGGER.info(ex.getMessage());
    }

    LOGGER.info("nbr of key pairs generated: " + nbrKeyPairsGenerated.toString());
    LOGGER.info("key pair duration milliseconds: " + keyPairGenerationDurationMillis.toString());
    final long averageKeyPairGenerationMillis
            = keyPairGenerationDurationMillis.get() / nbrKeyPairsGenerated.longValue();
    LOGGER.info("average duration per key pair generated: " + averageKeyPairGenerationMillis);
    LOGGER.info("");
    LOGGER.info("nbr of certificates served: " + x509CertificateServer.getNbrCertificatesServed());
    LOGGER.info("certificate generation duration milliseconds: " + x509CertificateServer.getCertificateGenerationDurationMillis());
    final long averageCertificateGenerationMillis
            = x509CertificateServer.getCertificateGenerationDurationMillis() / (long) x509CertificateServer.getNbrCertificatesServed();
    LOGGER.info("average duration per certificate generated: " + averageCertificateGenerationMillis);

    final Timer timer = new Timer();
    timer.schedule(new ShutdownTimerTask(), 3000);

    // shut down executor threads to exit
    LOGGER.info("releasing server resources");
    serverBootstrap.releaseExternalResources();
    timer.cancel();
  }

  /** Provides a task to run when the external resources cannot be released. */
  private static final class ShutdownTimerTask extends TimerTask {

    /** Runs the timer task. */
    @Override
    public void run() {
      LOGGER.info("server resources not released");
      System.exit(0);
    }
  }

  /** Provides a task that runs a mock HTTP client for a certain number of iterations. */
  class MockHTTPClientTask implements Runnable {

    final CountDownLatch countDownLatch;
    final int threadNbr;
    int requestNbr = 0;

    MockHTTPClientTask(final CountDownLatch countDownLatch, final int threadNbr) {
      this.countDownLatch = countDownLatch;
      this.threadNbr = threadNbr;
    }

    @Override
    public void run() {
      Thread.currentThread().setName("thread " + threadNbr);
      LOGGER.info("**** starting " + Thread.currentThread().getName());
      for (int i = 0; i < 5; i++) {
        mockHTTPClient();
        LOGGER.info(Thread.currentThread().getName() + " generated certificate " + String.valueOf(i + 1));
      }
      LOGGER.info("**** finishing " + Thread.currentThread().getName());
      countDownLatch.countDown();
    }

    /** Tests the HTTP request and response messages. */
    @SuppressWarnings({"ThrowableResultIgnored", "null"})
    private void mockHTTPClient() {
      final ClientBootstrap clientBootstrap = new ClientBootstrap(new NioClientSocketChannelFactory(
              Executors.newCachedThreadPool(),
              Executors.newCachedThreadPool()));

      // configure the client pipeline
      final Object clientResume_lock = new Object();
      final AbstractHTTPResponseHandler httpResponseHandler = new MockHTTPResponseHandler(clientResume_lock);
      final X509SecurityInfo x509SecurityInfo = KeyStoreTestUtils.getClientX509SecurityInfo();
      final ChannelPipeline channelPipeline = HTTPClientPipelineFactory.getPipeline(
              httpResponseHandler,
              x509SecurityInfo);
      clientBootstrap.setPipeline(channelPipeline);
      LOGGER.debug("client pipeline: " + channelPipeline.toString());

      // start the connection attempt
      ChannelFuture channelFuture = clientBootstrap.connect(new InetSocketAddress("localhost", SERVER_PORT));

      // wait until the connection attempt succeeds or fails
      final Channel channel = channelFuture.awaitUninterruptibly().getChannel();
      if (!channelFuture.isSuccess()) {
        LOGGER.warn(StringUtils.getStackTraceAsString(channelFuture.getCause()));
        fail(channelFuture.getCause().getMessage());
      }
      LOGGER.debug(Thread.currentThread().getName() + " connected");

      URI uri = null;
      HttpRequest httpRequest;
      String host;

      // send the certificate request
      try {
        uri = new URI("https://localhost:" + SERVER_PORT + "/CA/certificate-request");
      } catch (URISyntaxException ex) {
        fail(ex.getMessage());
      }
      httpRequest = new DefaultHttpRequest(
              HttpVersion.HTTP_1_1,
              HttpMethod.POST,
              uri.toASCIIString());
      host = uri.getHost() == null ? "localhost" : uri.getHost();
      httpRequest.setHeader(HttpHeaders.Names.HOST, host);
      httpRequest.setHeader(HttpHeaders.Names.CONTENT_TYPE, "application/octet-stream");
      httpRequest.setHeader(HttpHeaders.Names.CONTENT_TRANSFER_ENCODING, HttpHeaders.Values.BINARY);
      httpRequest.setHeader(HttpHeaders.Names.USER_AGENT, Thread.currentThread().getName());

      final long startTimeMillis = System.currentTimeMillis();
      KeyPair clientKeyPair = null;
      try {
        clientKeyPair = X509Utils.generateRSAKeyPair2048();
      } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
        fail(ex.getMessage());
      }
      assertNotNull(clientKeyPair);
      nbrKeyPairsGenerated.getAndIncrement();
      keyPairGenerationDurationMillis.addAndGet(System.currentTimeMillis() - startTimeMillis);
      final byte[] serializedClientPublicKey = ByteUtils.serialize(clientKeyPair.getPublic());
      final char[] base64SerializedClientPublicKey = Base64Coder.encode(serializedClientPublicKey);
      LOGGER.debug("base64SerializedClientPublicKey length: " + base64SerializedClientPublicKey.length);
      final String base64SerializedClientPublicKeyString = new String(base64SerializedClientPublicKey);
      final ChannelBuffer channelBuffer = ChannelBuffers.copiedBuffer(base64SerializedClientPublicKeyString.getBytes());
      LOGGER.debug("content: " + new String(channelBuffer.array()));
      LOGGER.debug("content length: " + channelBuffer.array().length);
      httpRequest.setContent(channelBuffer);
      httpRequest.setHeader(HttpHeaders.Names.CONTENT_LENGTH, String.valueOf(channelBuffer.array().length));
      channel.write(httpRequest);

      // wait for the request message to be sent
      channelFuture.awaitUninterruptibly();
      if (!channelFuture.isSuccess()) {
        LOGGER.warn(StringUtils.getStackTraceAsString(channelFuture.getCause()));
        fail(channelFuture.getCause().getMessage());
      }

      // the message response handler will signal this thread when the test exchange is completed
      LOGGER.debug(Thread.currentThread().getName() + " client waiting for server to process the request");
      synchronized (clientResume_lock) {
        try {
          clientResume_lock.wait();
        } catch (InterruptedException ex) {
        }
      }
      LOGGER.debug("client releasing HTTP resources");
      channel.close();
      clientBootstrap.releaseExternalResources();
    }
  }
}
