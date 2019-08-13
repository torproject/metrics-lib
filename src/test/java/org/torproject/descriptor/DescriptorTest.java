/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

@RunWith(Parameterized.class)
public class DescriptorTest {

  /** Different descriptor files. */
  @Parameters
  public static Collection<Object[]> pathFilename() {
    return Arrays.asList(
        new Object[][] {
          {"other/2017-07-17-17-02-00", // test-filename in src/test/resources
           ExitList.class, // descriptor type, i.e., the most specific interface
           new String[] {"@type tordnsel 1.0"}, // all annotations
              1}, // expected descriptor count in descriptor file

          {"other/op-nl-5242880-2017-07-17.tpf",
           TorperfResult.class,
           new String[] {"@type torperf 1.1"},
              4},

          {"relay/2017-07-17-17-00-00-consensus",
           RelayNetworkStatusConsensus.class,
           new String[] {"@type network-status-consensus-3 1.0"},
              1},

          {"relay/2017-07-17-17-00-00-consensus-microdesc",
           RelayNetworkStatusConsensus.class,
           new String[] {"@type network-status-microdesc-consensus-3 1.0"},
              1},

          {"relay/2017-07-17-17-00-00-vote-0232AF901C31A04EE9848595AF9BB"
             + "7620D4C5B2E-6C2F5B0D52DFB3E4CA3DDEEAD690CC563CAF0601",
           RelayNetworkStatusVote.class,
           new String[] {"@type network-status-vote-3 1.0"},
              1},

          {"relay/2017-07-17-17-20-00-extra-infos",
           RelayExtraInfoDescriptor.class,
           new String[] {"@type extra-info 1.0"},
              6},

          {"relay/2017-07-17-17-20-00-micro",
           Microdescriptor.class,
           new String[] {"@type microdescriptor 1.0"},
              14},

          {"relay/2017-07-17-17-20-00-server-descriptors",
           RelayServerDescriptor.class,
           new String[] {"@type server-descriptor 1.0"},
              4},

          {"bridge/20170717-170645-1D8F3A91C37C5D1C4C19B1AD1D0CFBE8BF72D8E1",
           BridgeNetworkStatus.class,
           new String[] {"@type bridge-network-status 1.2"},
              1},

          {"bridge/2017-07-17-17-09-00-extra-infos",
           BridgeExtraInfoDescriptor.class,
           new String[] {"@type bridge-extra-info 1.3"},
              6},

          {"bridge/2017-07-17-17-09-00-server-descriptors",
           BridgeServerDescriptor.class,
           new String[] {"@type bridge-server-descriptor 1.2"},
              13},

          {"snowflake/example_metrics.log",
           SnowflakeStats.class,
           new String[0],
              2}
        });
  }

  private int expDescCount;
  private int annoCount;
  private String[] annos;
  private String filename;
  private File fileForName;
  private Class descClass;
  private Iterator<Descriptor> descs;

  /** This constructor receives the above defined data for each run. */
  public DescriptorTest(String fn, Class clazz, String[] annos,
      int expDescCount) throws Exception {
    this.filename = fn;
    this.fileForName = new File(fn);
    this.expDescCount = expDescCount;
    this.annos = annos;
    this.annoCount = annos.length;
    this.descClass = clazz;
    this.descs = DescriptorSourceFactory.createDescriptorParser()
        .parseDescriptors(bytesFromResource(), fileForName, filename)
        .iterator();
  }

  @Test
  public void testCounts() {
    int descCount = 0;
    while (descs.hasNext()) {
      Descriptor desc = descs.next();
      descCount++;
      assertEquals(filename + ": Invalid annotation count.",
          annoCount, desc.getAnnotations().size());
    }
    assertEquals("Content of " + filename + ".", expDescCount, descCount);
  }

  @Test
  public void testNewline() {
    while (descs.hasNext()) {
      Descriptor desc = descs.next();
      byte[] raw = desc.getRawDescriptorBytes();
      assertEquals(filename + ": Newline missing.", '\n', raw[raw.length - 1]);
    }
  }

  @Test
  public void testTypes() {
    while (descs.hasNext()) {
      Descriptor desc = descs.next();
      assertTrue(filename + ": Expected " + descClass.getName()
          + ", but received: "
          + Arrays.toString(desc.getClass().getInterfaces()),
          Arrays.asList(desc.getClass().getInterfaces()).contains(descClass));
    }
  }

  @Test
  public void testAnnotations() {
    while (descs.hasNext()) {
      Descriptor desc = descs.next();
      for (String anno : annos) {
        assertTrue(filename + ": Annotation '" + anno + "' missing in "
            + Arrays.toString(annos), desc.getAnnotations().contains(anno));
      }
    }
  }

  private byte[] bytesFromResource() throws Exception {
    StringBuilder sb = new StringBuilder();
    BufferedReader br = new BufferedReader(new InputStreamReader(getClass()
        .getClassLoader().getResourceAsStream(filename)));
    String line = br.readLine();
    while (null != line) {
      sb.append(line).append('\n');
      line = br.readLine();
    }
    return sb.toString().getBytes();
  }

}
