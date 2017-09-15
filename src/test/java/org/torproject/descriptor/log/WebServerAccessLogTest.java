/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class WebServerAccessLogTest {

  /** Test data structure: given line, cleaned line, valid, filename. */
  @Parameters
  public static Collection<Object[]> logData() {
    return Arrays.asList(new Object[][] {
        { "0.0.0.0 - - [20/Sep/2017:00:00:00 +0000] "
          + "\"GET /fonts/WOFF/OTF/SourceSansPro-It.otf.woff HTTP/1.1\" "
          + "200 50556 \"https://metrics.torproject.org/\" \"-\" -",
          "0.0.0.0 - - [20/Sep/2017:00:00:00 +0000] \"GET "
          + "/fonts/WOFF/OTF/SourceSansPro-It.otf.woff HTTP/1.1\" 200 50556\n",
          Boolean.TRUE, "virt.host0_phys.host1a_access.log_20170920"},
        { "127.0.0.1 qwer 123 [30/May/2017:06:07:08 +0000] "
          + "\"GET /server-status?auto HTTP/1.1\" 333 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET /server-status"
          + " HTTP/1.1\" 333 294\n", Boolean.TRUE,
          "virt.host1_phys.host2a_access.log_20170530"},
        { "0.0.0.3 abc 567 [30/May/2017:06:07:08 +0000] "
          + "\"GET /server-status?auto HTTP/1.1\" 333 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "0.0.0.3 - - [30/May/2017:00:00:00 +0000] \"GET /server-status"
          + " HTTP/1.1\" 333 294\n", Boolean.TRUE,
          "virt-host1_phys.host2a_access.log_20170530"},
        { "11.22.33.44 - - [30/Jul/2017:15:16:17 +0000] "
          + "\"GET http://www.torproject.org/favicon.ico HTTP/1.1\" "
          + "100 536 \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0;"
          + " SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.5.2; "
          + ".NET CLR 3.5.30729; .NET CLR 3.0.30618)\"",
          "0.0.0.0 - - [30/Jul/2017:00:00:00 +0000] "
          + "\"GET http://www.torproject.org/favicon.ico HTTP/1.1\" "
          + "100 536\n", Boolean.TRUE,
          "virt.host1_phys.host2b_access.log_20170730"},
        { "abcdefghijklmnop1234567890", "", Boolean.FALSE,
          "vhost1_phys.host2c_access.log_20170731.log"},
        { "", "", Boolean.FALSE, "host2d_host1_access.log_20170731.log"},
        { "0.0.0.0 - - [30/May/2017:00:00:00 +0000] "
          + "\"GET /server-status HTTP/1.1\" 200 1294 \"-\" \"-\" -",
          "0.0.0.0 - - [30/May/2017:00:00:00 +0000] \"GET "
          + "/server-status HTTP/1.1\" 200 1294\n", Boolean.TRUE,
          "some/other/path/virtual_physical_access.log_20170530.log"}
        });
  }

  private String real;
  private String clean;
  private int count;
  private boolean valid;
  private String fn;
  private File file;

  /** Set the above test data. */
  public WebServerAccessLogTest(String in, String out, boolean valid,
      String filename) {
    this.real = in;
    this.clean = out;
    this.valid = valid;
    this.fn = filename;
    this.file = new File(filename);
  }

  @Test
  public void testValidation() throws Exception {
    WebServerAccessLogImpl wsal
        = new WebServerAccessLogImpl(real.getBytes(), file);
    wsal.validate();
    if (valid) {
      assertEquals(0, wsal.getUnrecognizedLines().size());
    } else {
      if (!real.isEmpty()) {
        assertEquals(real, wsal.getUnrecognizedLines().get(0));
      }
    }
  }

}

