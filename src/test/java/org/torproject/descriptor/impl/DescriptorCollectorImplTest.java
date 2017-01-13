/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import java.util.SortedMap;

import org.junit.Test;

public class DescriptorCollectorImplTest {

  private static final String REMOTE_DIRECTORY_CONSENSUSES =
      "/recent/relay-descriptors/consensuses/";

  @Test()
  public void testOneFile() {
    String remoteFilename = "2015-05-24-12-00-00-consensus";
    String directoryListing = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td><td>"
        + "<a href=\"" + remoteFilename + "\">"
        + "2015-05-24-12-00-00-consensus</a></td>"
        + "<td align=\"right\">2015-05-24 12:08  </td>"
        + "<td align=\"right\">1.5M</td><td>&nbsp;</td></tr>";
    SortedMap<String, Long> remoteFiles =
        new DescriptorCollectorImpl().parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNotNull(remoteFiles);
    assertSame(1, remoteFiles.size());
    assertEquals(REMOTE_DIRECTORY_CONSENSUSES + remoteFilename,
        remoteFiles.firstKey());
    assertEquals((Long) 1432469280000L,
        remoteFiles.get(remoteFiles.firstKey()));
  }

  @Test()
  public void testSameFileTwoTimestampsLastWins() {
    String remoteFilename = "2015-05-24-12-00-00-consensus";
    String firstTimestamp = "2015-05-24 12:04";
    String secondTimestamp = "2015-05-24 12:08";
    String lineFormat = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td><td>"
        + "<a href=\"%s\">2015-05-24-12-00-00-consensus</a></td>"
        + "<td align=\"right\">%s  </td>"
        + "<td align=\"right\">1.5M</td><td>&nbsp;</td></tr>\n";
    String directoryListing = String.format(lineFormat + lineFormat,
        remoteFilename, firstTimestamp, remoteFilename, secondTimestamp);
    SortedMap<String, Long> remoteFiles =
        new DescriptorCollectorImpl().parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNotNull(remoteFiles);
    assertSame(1, remoteFiles.size());
    assertEquals(REMOTE_DIRECTORY_CONSENSUSES + remoteFilename,
        remoteFiles.firstKey());
    assertEquals((Long) 1432469280000L,
        remoteFiles.get(remoteFiles.firstKey()));
  }

  @Test()
  public void testSubDirectoryOnly() {
    String directoryListing = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/folder.gif\" alt=\"[DIR]\"></td><td>"
        + "<a href=\"subdir/\">subdir/</a></td>"
        + "<td align=\"right\">2015-05-27 14:07  </td>"
        + "<td align=\"right\">  - </td><td>&nbsp;</td></tr>";
    DescriptorCollectorImpl collector = new DescriptorCollectorImpl();
    SortedMap<String, Long> remoteFiles = collector.parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNotNull(remoteFiles);
    assertTrue(remoteFiles.isEmpty());
  }

  @Test()
  public void testParentDirectoryOnly() {
    String directoryListing = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/back.gif\" alt=\"[DIR]\"></td><td>"
        + "<a href=\"/recent/relay-descriptors/\">Parent Directory</a>"
        + "</td><td>&nbsp;</td><td align=\"right\">  - </td>"
        + "<td>&nbsp;</td></tr>";
    DescriptorCollectorImpl collector = new DescriptorCollectorImpl();
    SortedMap<String, Long> remoteFiles = collector.parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNotNull(remoteFiles);
    assertTrue(remoteFiles.isEmpty());
  }

  @Test()
  public void testUnexpectedDateFormat() {
    String directoryListing = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td><td>"
        + "<a href=\"2015-05-24-12-00-00-consensus\">"
        + "2015-05-24-12-00-00-consensus</a></td>"
        + "<td align=\"right\">24-May-2015 12:08  </td>"
        + "<td align=\"right\">1.5M</td><td>&nbsp;</td></tr>";
    SortedMap<String, Long> remoteFiles =
        new DescriptorCollectorImpl().parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNotNull(remoteFiles);
    assertTrue(remoteFiles.isEmpty());
  }

  @Test()
  public void testInvalidDate() {
    String directoryListing = "<tr><td valign=\"top\">"
        + "<img src=\"/icons/unknown.gif\" alt=\"[   ]\"></td><td>"
        + "<a href=\"2015-05-24-12-00-00-consensus\">"
        + "2015-05-24-12-00-00-consensus</a></td>"
        + "<td align=\"right\">2015-05-34 12:08  </td>"
        + "<td align=\"right\">1.5M</td><td>&nbsp;</td></tr>";
    SortedMap<String, Long> remoteFiles =
        new DescriptorCollectorImpl().parseDirectoryListing(
        REMOTE_DIRECTORY_CONSENSUSES, directoryListing);
    assertNull(remoteFiles);
  }
}

