/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.List;

/* Test parsing of descriptors. */
public class DescriptorImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  private static final String DESC = Key.CRYPTO_BEGIN.keyword
      + "\ncryptostuff\ncryptique\n" + Key.CRYPTO_END.keyword;
  private static final String KW = "dummy-kw";
  private static final String NL = "\n";
  private static final byte[] DESCBYTES1 = DESC.getBytes();
  private static final byte[] DESCBYTES2 = (DESC + "\n" + DESC).getBytes();
  private static final byte[] DESCBYTES3
      = (KW + NL + DESC + KW + NL + DESC + KW + NL).getBytes();

  @Test
  public void testSplitByKey() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES2);
    List<int[]> res = des.splitByKey(Key.CRYPTO_BEGIN, 0, DESCBYTES2.length,
        false);
    int count = 0;
    for (int[] i : res) {
      assertEquals("Offset.", count * 42, i[0]);
      assertEquals("Length.", 42 - count++, i[1]);
    }
  }

  @Test
  public void testDigestsSha256Base64() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES3);
    des.calculateDigestSha256Base64(KW);
    assertEquals("1bEECw9nT5KRzPG8dAzEFJgSI4OBQfyWn+wjREb8oa8",
        des.getDigestSha256Base64());
    assertNull(des.getDigestSha1Hex());
  }

  private TestDescriptor makeTestDesc(byte[] bytes) throws Exception {
    return new TestDescriptor(bytes, new int[]{0, bytes.length}, false, false);
  }

  @Test
  public void testDigestsSha256Base64EndToken() throws Exception {
    TestDescriptor des = this.makeTestDesc(DESCBYTES3);
    des.calculateDigestSha256Base64(KW, KW);
    assertEquals("MHFj9sNLRXdDo/O62uJgNujuNnNbCtpUZiGwthfLH9E",
        des.getDigestSha256Base64());
    assertNull(des.getDigestSha1Hex());
  }

  @Test
  public void testDigestsSha1Hex() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES3);
    des.calculateDigestSha1Hex(KW, KW);
    assertEquals("2fc934e9523937c07cb9f4b395827a11c7b18c9d",
        des.getDigestSha1Hex());
    assertNull(des.getDigestSha256Base64());
  }

  @Test
  public void testDigestsSha1HexNoToken() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES1);
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Could not calculate descriptor digest.");
    des.calculateDigestSha1Hex(KW, KW);
  }

  @Test
  public void testNoAnnotation() throws Exception {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Annotation line does not contain a newline.");
    TestDescriptor des = makeTestDesc("@@@".getBytes());
  }

  @Test
  public void testDescriptorEmpty() throws Exception {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Descriptor is empty.");
    TestDescriptor des = makeTestDesc("".getBytes());
  }

  @Test
  public void testDescriptorBlankLine() throws Exception {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Blank lines are not allowed.");
    TestDescriptor des = makeTestDesc("\n\n".getBytes());
  }

  @Test
  public void testDigestsNothing() throws Exception {
    TestDescriptor des = makeTestDesc("\n".getBytes());
    des.checkFirstKey(Key.EMPTY);
    des.checkLastKey(Key.EMPTY);
  }

  @Test
  public void testDigestsOnlyAnnotations() throws Exception {
    TestDescriptor des = makeTestDesc("@a@b\n".getBytes());
    des.checkFirstKey(Key.EMPTY);
    des.checkLastKey(Key.EMPTY);
  }

  @Test
  public void testDigestsSha256Base64NoToken() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES1);
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage("Could not calculate descriptor digest.");
    des.calculateDigestSha256Base64(KW);
  }

  @Test
  public void testDigestsSha256Base64NoReCalculation() throws Exception {
    TestDescriptor des = makeTestDesc(DESCBYTES3);
    des.calculateDigestSha256Base64(KW);
    String digest = des.getDigestSha256Base64();
    assertEquals("1bEECw9nT5KRzPG8dAzEFJgSI4OBQfyWn+wjREb8oa8", digest);
    des.calculateDigestSha256Base64(Key.CRYPTO_END.keyword);
    digest = des.getDigestSha256Base64();
    assertEquals("1bEECw9nT5KRzPG8dAzEFJgSI4OBQfyWn+wjREb8oa8", digest);
  }
}


