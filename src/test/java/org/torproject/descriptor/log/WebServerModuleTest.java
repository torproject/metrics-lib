/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import static org.junit.Assert.assertEquals;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.internal.FileType;

import org.hamcrest.Matchers;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.Arrays;
import java.util.stream.Collectors;

/** This class contains various tests for the webstats module. */
public class WebServerModuleTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testWrongFormat() throws Exception {
    String filename = "h1_phys1_access.log_no-date.log";
    thrown.expect(DescriptorParseException.class);
    thrown.expectMessage(Matchers
         .containsString("Cannot parse WebServerAccessLog file: "
         + filename));
    new WebServerAccessLogImpl(new byte[0], null, filename);
  }

  @Test
  public void testDateFormat() throws Exception {
    String filename = "h2_phys2_access.log_05001713";
    thrown.expect(DescriptorParseException.class);
    thrown.expectMessage(Matchers
         .containsString("Cannot parse WebServerAccessLog file: "
         + filename));
    new WebServerAccessLogImpl(new byte[0], null, filename);
  }

  @Test
  public void testNoParentPathRoot() throws Exception {
    String filename = "h3_access.log_05001213";
    thrown.expect(DescriptorParseException.class);
    thrown.expectMessage(Matchers
         .containsString("WebServerAccessLog "
         + "file name doesn't comply to standard: " + filename));
    new WebServerAccessLogImpl(new byte[0], null, filename);
  }

  @Test
  public void testNoParentPathThis() throws Exception {
    String filename = "_h3_access.log_05001213";
    thrown.expect(DescriptorParseException.class);
    thrown.expectMessage(Matchers
         .containsString("WebServerAccessLog "
         + "file name doesn't comply to standard: " + filename));
    new WebServerAccessLogImpl(new byte[0], null, filename);
  }

  @Test
  public void testNoParentPathParent() throws Exception {
    String filename = "h3__access.log_05001213";
    thrown.expect(DescriptorParseException.class);
    thrown.expectMessage(Matchers
         .containsString("WebServerAccessLog "
         + "file name doesn't comply to standard: " + filename));
    new WebServerAccessLogImpl(new byte[0], null, filename);
  }

  private static String[] logLines = {
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1205",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1203",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1207",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1204",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1202",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1206",
      "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
      + "/server-status HTTP/1.1\" 200 1201"
  };

  private static String logText = Arrays.stream(logLines)
      .map((String line) -> line + (" some content"))
      .collect(Collectors.joining("\n"));

  @Test
  public void testBasics() throws Exception {
    WebServerAccessLogImpl wsal = new WebServerAccessLogImpl(logText.getBytes(),
        null, "vhost_host7_access.log_20170530");
    assertEquals(wsal.getAnnotations().size(), 0);
    assertEquals(logText,
        new String(FileType.XZ.decompress(wsal.getRawDescriptorBytes())));
    assertEquals("host7", wsal.getPhysicalHost());
    assertEquals("vhost", wsal.getVirtualHost());
  }

}

