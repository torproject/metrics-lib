/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class DescriptorParserImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private TestDescriptor makeTestDesc(byte[] bytes) throws Exception {
    return new TestDescriptor(bytes, new int[]{0, bytes.length}, false, false);
  }

  private static final String MICRO =
      "@type microdescriptor 1.0\n"
      + "onion-key\n"
      + "-----BEGIN RSA PUBLIC KEY-----\n"
      + "MIGJAoGBALzJLYYlkTv6tPet3vusug9judCTrN6MzthV1xVGMSuuWtGHhOJDaIPG\n"
      + "hKdp99CAIU3sLXYO6zDQRF8PL/Z1GK3c+QHuotzfHotR7fMGtUQWNZRs9glVrVdj\n"
      + "6KGAHFHo+9qs6NPg7Ux8Minw3wuaHCqoFbQVXo8F+S3wJE6YQ37HAgMBAAE=\n"
      + "-----END RSA PUBLIC KEY-----\n"
      + "ntor-onion-key RYjTCjtZRvOyfatfubhOjcEib/yDMsyJcjPT82mf6VA=\n"
      + "id ed25519 ihsbrlWToq8b01rvfszqqTMUl2ulyPV3TniKuTENCzY\n";

  @Test
  public void testAnnotation() throws Exception {
    TestDescriptor des = makeTestDesc(MICRO.getBytes());
    DescriptorParserImpl dpi = new DescriptorParserImpl();
    assertEquals(1,
        dpi.parseDescriptors(des.getRawDescriptorBytes(), "dummy.file").size());
  }

}

