/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.Microdescriptor;

import org.junit.Test;

public class MicrodescriptorImplTest {

  /* Helper class to build a microdescriptor based on default data and
   * modifications requested by test methods. */
  private static class DescriptorBuilder {

    private String onionKeyLines = "onion-key\n"
        + "-----BEGIN RSA PUBLIC KEY-----\n"
        + "MIGJAoGBALNZ4pNsHHkl7a+kFWbBmPHNAepjjvuhjTr1TaMB3UKuCRaXJmS2Qr"
        + "CW\nkTmINqdQUccwb3ghb7EBZfDtCUvjcwMSEsRRTVIZqVQsYj6m3n1CegOc4o"
        + "UutXaZ\nfkyty5XOgV4Qucx9wokzTMCHlO0V0x9y0FwFsK5Nb6ugqfQLLQ6XAg"
        + "MBAAE=\n"
        + "-----END RSA PUBLIC KEY-----";

    private static Microdescriptor createWithDefaultLines()
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      return new MicrodescriptorImpl(db.buildDescriptor(), true);
    }

    private String ntorOnionKeyLine =
        "ntor-onion-key PXLa7IGE+TzPDMsM5j9rFnDa37rd6kfZa5QuzqqJukw=";

    private String idLine = "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8";

    private static Microdescriptor createWithIdLine(String line)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.idLine = line;
      return new MicrodescriptorImpl(db.buildDescriptor(), true);
    }

    private byte[] buildDescriptor() {
      StringBuilder sb = new StringBuilder();
      if (this.onionKeyLines != null) {
        sb.append(this.onionKeyLines).append("\n");
      }
      if (this.ntorOnionKeyLine != null) {
        sb.append(this.ntorOnionKeyLine).append("\n");
      }
      if (this.idLine != null) {
        sb.append(this.idLine).append("\n");
      }
      return sb.toString().getBytes();
    }
  }

  @Test()
  public void testDefaults() throws DescriptorParseException {
    DescriptorBuilder.createWithDefaultLines();
  }

  @Test(expected = DescriptorParseException.class)
  public void testIdRsa1024TooShort() throws DescriptorParseException {
    DescriptorBuilder.createWithIdLine("id rsa1024 AAAA");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIdRsa1024TooLong() throws DescriptorParseException {
    DescriptorBuilder.createWithIdLine("id ed25519 AAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIdRsa512() throws DescriptorParseException {
    DescriptorBuilder.createWithIdLine("id rsa512 "
        + "bvegfGxp8k7T9QFpjPTrPaJTa/8");
  }

  @Test(expected = DescriptorParseException.class)
  public void testIdEd25519Duplicate() throws DescriptorParseException {
    DescriptorBuilder.createWithIdLine(
        "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8\n"
        + "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8");
  }
}
