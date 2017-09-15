/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Parameterized.class)
public class WebServerAccessLogLineTest {

  /** Test data structure:
   * reference date, real log line, cleaned line, is valid.
   */
  @Parameters
  public static Collection<Object[]> logData() {
    return Arrays.asList(new Object[][] {
        { "0.0.0.0 - - [22/Jan/2018:00:00:00 +0000] \"GET "
          + "/collector/archive HTTP/1.1\" 301 -",
          "0.0.0.0 - - [22/Jan/2018:00:00:00 +0000] \"GET "
          + "/collector/archive HTTP/1.1\" 301 -", Boolean.TRUE},
        { "0.0.0.0 - - [22/Jan/2018:00:00:00 +0000] \"GET "
          + "/collector/archive HTTP/1.1\" 301 X \"ccc\"",
          "", Boolean.FALSE},
        { "123.98.100.23 xyz xyz [22/Jan/2018:01:20:03 +0000] \"GET "
          + "/collector/archive HTTP/1.1\" 301 - xyz abc xxxXXXXXXXX",
          "123.98.100.23 - - [22/Jan/2018:00:00:00 +0000] \"GET "
          + "/collector/archive HTTP/1.1\" 301 -", Boolean.TRUE},
        { "127.0.0.1 abc xyz [03/May/2017:06:07:08 +0000] "
          + "\"GET /server-status HTTP/1.1\" 303 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "127.0.0.1 - - [03/May/2017:00:00:00 +0000] \"GET /server-status"
          + " HTTP/1.1\" 303 294", Boolean.TRUE},
        { "127.0.0.1 abc xyz [03/May/2017:06:07:08 +0000] "
          + "\"GET /server-status?auto HTTP/1.1\" 303 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "127.0.0.1 - - [03/May/2017:00:00:00 +0000] \"GET /server-status"
          + "?auto HTTP/1.1\" 303 294", Boolean.TRUE},
        { "42.41.40.39 - - [04/May/2017:06:07:08 +0000] "
          + "\"HEAD /server-status?auto HTTP/1.1\" 200 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "42.41.40.39 - - [04/May/2017:00:00:00 +0000] \"HEAD /server-status"
          + "?auto HTTP/1.1\" 200 294", Boolean.TRUE},
        { "42.41.39 - - [04/May/2017:06:07:08 +0000] "
          + "\"HEAD /server-status?auto HTTP/1.1\" 200 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "", Boolean.FALSE},
        { "42.41.40.1039 - - [04/May/2017:06:07:08 +0000] "
          + "\"HEAD /server-status?auto HTTP/1.1\" 200 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "", Boolean.FALSE},
        { "42.41.40_039 - - [04/May/2017:06:07:08 +0000] "
          + "\"HEAD /server-status?auto HTTP/1.1\" 200 294 "
          + "\"-\" \"munin/2.0.25-1+deb8u3 (libwww-perl/6.08)\"",
          "", Boolean.FALSE},
        { "0.0.0.2 - - [05/May/2017:15:16:17 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "404 536 \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0;"
          + " SLCC1; .NET CLR 2.0.50; Media Center PC 5.0; .NET CLR 3.5.2;\"",
          "0.0.0.2 - - [05/May/2017:00:00:00 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "404 536",
          Boolean.TRUE},
        { "0.0.0.99 - - [05/June/2017:15:16:17 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico FTP/1.0\" "
          + "300 536 \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0;"
          + " SLCC1; .NET CLR 2.0.50; Media Center PC 5.0; .NET CLR 3.5.2;\"",
          "", Boolean.FALSE},
        { "0.0.0.99 - - [05/Jun/2017:15:16:17 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico FTP/1.0\" "
          + "300 536 \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0;"
          + " SLCC1; .NET CLR 2.0.50; Media Center PC 5.0; .NET CLR 3.5.2;\"",
          "0.0.0.99 - - [05/Jun/2017:00:00:00 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico FTP/1.0\" 300 536",
          Boolean.TRUE},
        { "0.0.0.7 - - [06/May/2017:00:16:17 +0100] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536 \"-\" \"Mozilla/4.0 (compatible; Opera 7.0; Windows 6.0;"
          + " funky values ; \"",
          "0.0.0.7 - - [05/May/2017:00:00:00 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536", Boolean.TRUE},
        { "0.0.0.1 - - [07/Dec/2016:20:16:18 -1000] "
          + "\"GET http://t3.torproject.org/?query=what HTTP/1.1\" "
          + "200 777 \"-\" \"Mozilla/4.0 (compatible; MSIE 7.0; Windows 10;"
          + " SLCC1; .NET CLR 2.0; Media Center PC 5.0; .NET CLR 3.5.2)\"",
          "0.0.0.1 - - [08/Dec/2016:00:00:00 +0000] "
          + "\"GET http://t3.torproject.org/?query=what HTTP/1.1\" 200 777",
          Boolean.TRUE},
        { "abcdefghijklmnop1234567890", "", Boolean.FALSE},
        { "", "", Boolean.FALSE},
        { "0.0.0.7 - - [06/May/2017:00:16:17 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536 \"-\" \"Mozilla/4.0 (compatible; Opera 7.0; Windows 8.0;",
          "0.0.0.7 - - [06/May/2017:00:00:00 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536", Boolean.TRUE},
        { "0.0.0.7 - - [06/May/2017:00:16:17 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536 \"-\" \"Mozilla/4.0 (compatible; Opera 7.0; Windows XT;",
          "0.0.0.7 - - [06/May/2017:00:00:00 +0000] "
          + "\"GET http://metrics.torproject.org/favicon.ico HTTP/1.1\" "
          + "333 536", Boolean.TRUE},
        { "0.0.0.0 - - [08/May/2017:00:00:00 +0000] "
          + "\"GET /server-status HTTP/1.1\" 200 1294",
          "0.0.0.0 - - [08/May/2017:00:00:00 +0000] \"GET "
          + "/server-status HTTP/1.1\" 200 1294", Boolean.TRUE}
        });
  }

  @Parameter(0)
  public String real;

  @Parameter(1)
  public String clean;

  @Parameter(2)
  public boolean valid;

  @Test
  public void testValidation() {
    WebServerAccessLogLine line = WebServerAccessLogLine.makeLine(real);
    assertEquals("Failed on line: " + real, valid, line.isValid());
    assertEquals("Failed on line: " + real, clean, line.toLogString());
    if (valid && !"".equals(clean)) { // A cleaned, accepted line is valid.
      assertEquals("Failed on line: " + clean, clean,
          WebServerAccessLogLine.makeLine(clean).toLogString());
    }
  }

}

