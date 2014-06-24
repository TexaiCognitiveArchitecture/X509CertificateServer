/*
 * X509CertificateClientTest.java
 *
 * Created on Jun 30, 2008, 7:33:43 AM
 *
 * Description: .
 *
 * Copyright (C) May 20, 2010 reed.
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
package org.texai.x509certificateserver.util;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertPath;
import java.util.List;
import java.security.cert.X509Certificate;
import org.apache.log4j.Logger;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.texai.x509.KeyStoreTestUtils;
import org.texai.x509.X509SecurityInfo;
import org.texai.x509.X509Utils;
import static org.junit.Assert.*;

/**
 *
 * @author reed
 */
public class X509CertificateClientTest {

  /** the logger */
  private static final Logger LOGGER = Logger.getLogger(X509CertificateClientTest.class);
  // for SSL debugging
  static {
    System.setProperty("javax.net.debug", "all");
  }

  public X509CertificateClientTest() {
  }

  @BeforeClass
  public static void setUpClass() throws Exception {
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
   * Test of getIssuingCertificatePath method, of class X509CertificateClient.
   */
  @Test
  public void testGetIssuingCertificate() {
    LOGGER.info("getIssuingCertificate");
    KeyPair keyPair = null;
    try {
      keyPair = X509Utils.generateRSAKeyPair3072();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException ex) {
      fail(ex.getMessage());
    }
    assertNotNull(keyPair);
    PublicKey publicKey = keyPair.getPublic();
    X509CertificateClient instance = new X509CertificateClient();
    final X509SecurityInfo x509SecurityInfo = KeyStoreTestUtils.getClientX509SecurityInfo();
    CertPath result = instance.getIssuingCertificatePath(publicKey, x509SecurityInfo);
    assertNotNull(result);
    LOGGER.info(result);
    final List<?> certificates = result.getCertificates();
    assertNotNull(certificates);
    assertEquals(1, certificates.size());
    final X509Certificate x509Certificate = (X509Certificate) certificates.get(0);
    assertEquals("CN=texai.org, O=Texai Certification Authority, UID=ed6d6718-80de-4848-af43-fed7bdba3c36", x509Certificate.getIssuerDN().toString());
  }
}
