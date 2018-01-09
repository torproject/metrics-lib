/* Copyright 2015--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.Microdescriptor;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class MicrodescriptorImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

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
      return db.buildDescriptor();
    }

    private String ntorOnionKeyLine =
        "ntor-onion-key PXLa7IGE+TzPDMsM5j9rFnDa37rd6kfZa5QuzqqJukw=";

    private String idLine = "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8";

    private static Microdescriptor createWithIdLine(String line)
        throws DescriptorParseException {
      DescriptorBuilder db = new DescriptorBuilder();
      db.idLine = line;
      return db.buildDescriptor();
    }

    private byte[] buildDescriptorBytes() {
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

    private Microdescriptor buildDescriptor()
        throws DescriptorParseException {
      byte[] descriptorBytes = this.buildDescriptorBytes();
      return new MicrodescriptorImpl(descriptorBytes,
          new int[] { 0, descriptorBytes.length }, null);
    }
  }

  @Test
  public void testDefaults() throws DescriptorParseException {
    Microdescriptor micro = DescriptorBuilder.createWithDefaultLines();
    assertEquals("ER1AC4KqT//o3pJDrqlmej5G2qW1EQYEr/IrMQHNc6I",
        micro.getDigestSha256Base64());
  }

  @Test
  public void testIdRsa1024TooShort() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'AAAA' in line 'id rsa1024 AAAA' is not a "
        + "valid base64-encoded 20-byte value.");
    DescriptorBuilder.createWithIdLine("id rsa1024 AAAA");
  }

  @Test
  public void testIdRsa1024TooLong() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' in line 'id ed25519 "
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAA' is not a valid base64-encoded 32-byte value.");
    DescriptorBuilder.createWithIdLine("id ed25519 AAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
  }

  @Test
  public void testIdRsa512() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(
        "Illegal line 'id rsa512 bvegfGxp8k7T9QFpjPTrPaJTa/8'.");
    DescriptorBuilder.createWithIdLine("id rsa512 "
        + "bvegfGxp8k7T9QFpjPTrPaJTa/8");
  }

  @Test
  public void testIdEd25519Duplicate() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Keyword 'id' is contained 2 times, but must be"
        + " contained at most once.");
    DescriptorBuilder.createWithIdLine(
        "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8\n"
        + "id rsa1024 bvegfGxp8k7T9QFpjPTrPaJTa/8");
  }
}
