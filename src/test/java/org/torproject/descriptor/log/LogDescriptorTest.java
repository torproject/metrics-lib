/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

import static java.util.stream.Collectors.toList;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.LogDescriptor;
import org.torproject.descriptor.UnparseableDescriptor;
import org.torproject.descriptor.WebServerAccessLog;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

@RunWith(Parameterized.class)
public class LogDescriptorTest {

  /** Temporary folder containing all files for this test. */
  @Rule
  public TemporaryFolder temp = new TemporaryFolder();

  /** Directory containing two input descriptor files. */
  protected File indir;

  /** Descriptor reader used in this test. */
  protected DescriptorReader reader
      = DescriptorSourceFactory.createDescriptorReader();

  @Parameter(0)
  public boolean isDecompressedLog;

  @Parameter(1)
  public int size;

  @Parameter(2)
  public String[] pan;

  @Parameter(3)
  public Class<LogDescriptor> type;

  @Parameter(4)
  public int lineCount;

  /** All types of data that can be encountered during sync. */
  @Parameters
  public static Collection<Object[]> pathAndName() {
    return Arrays.asList(new Object[][] {
        {Boolean.FALSE, 1878, new String[]{"meronense.torproject.org",
            "metrics.torproject.org_meronense.torproject.org_access.log"
            + "_20170530.gz",
            "metrics.torproject.org", "20170530", "gz"},
         WebServerAccessLog.class, 24},
        {Boolean.TRUE, 1878, new String[]{"meronense.torproject.org",
            "xy.host.org_meronense.torproject.org_access.log_20170530.log",
            "metrics.torproject.org", "20170530", "xz"},
         WebServerAccessLog.class, 24},
        {Boolean.FALSE, 70730, new String[]{"archeotrichon.torproject.org",
            "archive.torproject.org_archeotrichon.torproject.org_access.log_"
            + "20151007.xz",
            "archive.torproject.org", "20151007", "xz"},
         WebServerAccessLog.class, 655},
        {Boolean.FALSE, 0, new String[]{"dummy.host.net",
            "nix.server.org_dummy.host.net_access.log_20111111.bz2",
            "nix.server.org", "20111111", "bz2"},
         WebServerAccessLog.class, 0}});
  }

  /** Prepares the temporary folder and writes files to it for this test. */
  private void createTemporaryFolderAndContents() throws IOException {
    this.indir = this.temp.newFolder();
    String path = this.pan[0];
    String name = this.pan[1];
    File logdir = new File(indir, path);
    logdir.mkdir();
    File accessLogFile = new File(logdir, name);
    Files.copy(getClass().getClassLoader().getResource(path + "/" + name)
        .openStream(), accessLogFile.toPath());
  }

  /** Read the test files. */
  @Before
  public void readAll() throws IOException {
    createTemporaryFolderAndContents();
    Iterator<Descriptor> descs = this.reader
        .readDescriptors(this.indir).iterator();
    while (descs.hasNext()) {
      descs.next();
    }
  }

  protected List<Descriptor> retrieve() throws Exception {
    assertEquals(1, this.reader.getParsedFiles().size());
    File logFile = new File(this.reader.getParsedFiles().firstKey());
    byte[] raw = Files.readAllBytes(logFile.toPath());
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    List<Descriptor> descs = new ArrayList<>();
    for (Descriptor desc
        : dp.parseDescriptors(raw, logFile, logFile.getName())) {
      descs.add(desc);
    }
    return descs;
  }

  @Test
  public void testParsing() throws Exception {
    List<Descriptor> descs = retrieve();
    assertTrue("Wrong type. " + dataUsed(),
        (descs.get(0) instanceof LogDescriptor));
    InternalLogDescriptor ld = (InternalLogDescriptor) descs.get(0);
    assertEquals("Wrong compression type string. " + dataUsed(),
        pan[4], ld.getCompressionType());
    List<? extends LogDescriptor.Line> lines
        = ld.logLines().collect(toList());
    assertEquals(this.lineCount, lines.size());
  }

  private String dataUsed() {
    return "Used data: " + Arrays.toString(pan);
  }

  @Test
  public void testUnknownLogType() throws Exception {
    assertEquals(dataUsed(), 1, this.reader.getParsedFiles().size());
    File logFile = new File(this.reader.getParsedFiles().firstKey());
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    File invalidFile = new File(this.reader.getParsedFiles().firstKey()
        .replace("access", "-"));
    List<Descriptor> descs = new ArrayList<>();
    for (Descriptor desc // note: only 'invalidFile' is used by LogDescriptor
        : dp.parseDescriptors(new byte[]{}, invalidFile, logFile.getName())) {
      descs.add(desc);
    }
    assertTrue(dataUsed() + "\nWrong type: "
        + Arrays.toString(descs.get(0).getClass().getInterfaces()),
        (descs.get(0) instanceof UnparseableDescriptor));
  }

  @Test
  public void testCompressionInvalid() throws Exception {
    if (isDecompressedLog) {
      return;
    }
    assertEquals(1, this.reader.getParsedFiles().size());
    File logFile = new File(this.reader.getParsedFiles().firstKey());
    byte[] raw = Files.readAllBytes(logFile.toPath());
    for (int i = 0; i < 3; i++) {
      raw[0] = (byte) i;
    }
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    List<Descriptor> descs = new ArrayList<>();
    for (Descriptor desc
           : dp.parseDescriptors(raw, logFile, logFile.getName())) {
      descs.add(desc);
    }
    assertTrue(dataUsed() + "\nWrong type: "
        + Arrays.toString(descs.get(0).getClass().getInterfaces()),
        (descs.get(0) instanceof UnparseableDescriptor));
    assertArrayEquals(dataUsed(), raw, descs.get(0).getRawDescriptorBytes());
  }
}

