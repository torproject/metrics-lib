/* Copyright 2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.onionperf;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.TorperfResult;

import org.apache.commons.compress.utils.IOUtils;
import org.junit.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class OnionPerfAnalysisConverterTest {

  private final String torperfResultTransfer1m1
      = "BUILDTIMES=0.15,0.22,0.34 CIRC_ID=39 CONNECT=1587991280.37 "
      + "DATACOMPLETE=1587991286.62 DATAPERC0=1587991283.81 "
      + "DATAPERC10=1587991284.15 DATAPERC100=1587991286.62 "
      + "DATAPERC20=1587991284.38 DATAPERC30=1587991284.66 "
      + "DATAPERC40=1587991284.93 DATAPERC50=1587991285.14 "
      + "DATAPERC60=1587991285.33 DATAPERC70=1587991285.67 "
      + "DATAPERC80=1587991285.85 DATAPERC90=1587991286.14 "
      + "DATAREQUEST=1587991283.36 DATARESPONSE=1587991283.81 DIDTIMEOUT=0 "
      + "ENDPOINTLOCAL=localhost:127.0.0.1:40878 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:35900 "
      + "ENDPOINTREMOTE=m3eahz7co6lzi6jn.onion:0.0.0.0:443 FILESIZE=1048576 "
      + "HOSTNAMELOCAL=op-nl2 HOSTNAMEREMOTE=op-nl2 LAUNCH=1587991281.38 "
      + "NEGOTIATE=1587991280.37 PARTIAL10240=1587991283.81 "
      + "PARTIAL102400=1587991284.15 PARTIAL1048576=1587991286.62 "
      + "PARTIAL20480=1587991283.81 PARTIAL204800=1587991284.38 "
      + "PARTIAL51200=1587991283.81 PARTIAL512000=1587991285.14 "
      + "PATH=$970F0966DAA7EBDEE44E3772045527A6854E997B,"
      + "$8101421BEFCCF4C271D5483C5AABCAAD245BBB9D,"
      + "$1A7A2516A961F2838F7F94786A8811BE82F9CFFE READBYTES=1048643 "
      + "REQUEST=1587991280.38 RESPONSE=1587991280.37 SOCKET=1587991280.37 "
      + "SOURCE=op-nl2 SOURCEADDRESS=unknown START=1587991280.37 "
      + "USED_AT=1587991286.62 USED_BY=71 WRITEBYTES=53";

  private final String torperfResultTransfer1m3
      = "BUILDTIMES=22.81,23.57,24.45 CIRC_ID=72 CONNECT=1587991880.37 "
      + "DATACOMPLETE=1587991927.74 DATAPERC0=1587991910.74 "
      + "DATAPERC10=1587991913.71 DATAPERC100=1587991927.74 "
      + "DATAPERC20=1587991916.00 DATAPERC30=1587991917.92 "
      + "DATAPERC40=1587991919.69 DATAPERC50=1587991921.80 "
      + "DATAPERC60=1587991923.35 DATAPERC70=1587991924.91 "
      + "DATAPERC80=1587991925.77 DATAPERC90=1587991927.04 "
      + "DATAREQUEST=1587991909.80 DATARESPONSE=1587991910.74 DIDTIMEOUT=0 "
      + "ENDPOINTLOCAL=localhost:127.0.0.1:41016 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:35900 "
      + "ENDPOINTREMOTE=3czoq6qyehjio6lcdo4tb4vk5uv2bm4gfk5iacnawza22do6klsj7wy"
      + "d.onion:0.0.0.0:443 FILESIZE=1048576 HOSTNAMELOCAL=op-nl2 "
      + "HOSTNAMEREMOTE=op-nl2 LAUNCH=1587991881.70 NEGOTIATE=1587991880.37 "
      + "PARTIAL10240=1587991910.74 PARTIAL102400=1587991913.71 "
      + "PARTIAL1048576=1587991927.74 PARTIAL20480=1587991910.74 "
      + "PARTIAL204800=1587991916.00 PARTIAL51200=1587991910.74 "
      + "PARTIAL512000=1587991921.80 "
      + "PATH=$D5C6F62A5D1B3C711CA5E6F9D3772A432E96F6C2,"
      + "$94EC34B871936504BE70671B44760BC99242E1F3,"
      + "$E0F638ECCE918B5455CE29D2CD9ECC9DBD8F8B21 READBYTES=1048643 "
      + "REQUEST=1587991880.37 RESPONSE=1587991880.37 SOCKET=1587991880.37 "
      + "SOURCE=op-nl2 SOURCEADDRESS=unknown START=1587991880.37 "
      + "USED_AT=1587991927.74 USED_BY=112 WRITEBYTES=53";

  private final String torperfResultTransfer50k2
      = "BUILDTIMES=0.09,0.15,0.27 CIRC_ID=49 CONNECT=1587991580.81 "
      + "DATACOMPLETE=1587991580.80 DATAPERC10=0.0 DATAPERC100=0.0 "
      + "DATAPERC20=0.0 DATAPERC30=0.0 DATAPERC40=0.0 DATAPERC50=0.0 "
      + "DATAPERC60=0.0 DATAPERC70=0.0 DATAPERC80=0.0 DATAPERC90=0.0 "
      + "DATAREQUEST=1587991580.80 DATARESPONSE=1587991580.80 DIDTIMEOUT=1 "
      + "ENDPOINTLOCAL=localhost:127.0.0.1:40948 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:35900 "
      + "ENDPOINTREMOTE=37.218.245.95:37.218.245.95:443 "
      + "ERRORCODE=TOR/END/MISC FILESIZE=51200 HOSTNAMELOCAL=op-nl2 "
      + "HOSTNAMEREMOTE=(null) LAUNCH=1587991454.80 NEGOTIATE=1587991580.81 "
      + "PATH=$12CF6DB4DAE106206D6C6B09988E865C0509843B,"
      + "$1DC17C4A52A458B5C8B1E79157F8665696210E10,"
      + "$39F17EC1BD41E652D1B80484D268E3933476FF42 READBYTES=0 "
      + "REQUEST=1587991580.84 RESPONSE=1587991580.80 SOCKET=1587991580.81 "
      + "SOURCE=op-nl2 SOURCEADDRESS=unknown START=1587991580.80 "
      + "USED_AT=1587991580.84 USED_BY=93 WRITEBYTES=0";

  @Test
  public void testAsTorperfResults() throws IOException,
      DescriptorParseException {
    List<String> expectedTorperfResults = new ArrayList<>();
    expectedTorperfResults.add(torperfResultTransfer1m1);
    expectedTorperfResults.add(torperfResultTransfer1m3);
    expectedTorperfResults.add(torperfResultTransfer50k2);
    URL resouce = getClass().getClassLoader().getResource(
        "onionperf/onionperf.analysis.json.xz");
    assertNotNull(resouce);
    InputStream compressedInputStream = resouce.openStream();
    assertNotNull(compressedInputStream);
    byte[] rawDescriptorBytes = IOUtils.toByteArray(compressedInputStream);
    OnionPerfAnalysisConverter onionPerfAnalysisConverter
        = new OnionPerfAnalysisConverter(rawDescriptorBytes, null);
    for (Descriptor descriptor
        : onionPerfAnalysisConverter.asTorperfResults()) {
      assertTrue(descriptor instanceof TorperfResult);
      String formattedTorperfResult
          = new String(descriptor.getRawDescriptorBytes()).trim();
      assertNotNull(formattedTorperfResult);
      String expectedTorperfResult = expectedTorperfResults.remove(0);
      assertEquals(expectedTorperfResult, formattedTorperfResult);
    }
    assertTrue(expectedTorperfResults.isEmpty());
  }

  private final String torperfResultStream155
      = "BUILDTIMES=0.62,0.90,1.26 CIRC_ID=1008 CONNECT=1594633118.41 "
      + "DATACOMPLETE=1594633145.46 DATAPERC0=1594633123.64 "
      + "DATAPERC10=1594633125.57 DATAPERC100=1594633145.46 "
      + "DATAPERC20=1594633127.56 DATAPERC30=1594633129.56 "
      + "DATAPERC40=1594633132.20 DATAPERC50=1594633134.29 "
      + "DATAPERC60=1594633136.41 DATAPERC70=1594633138.84 "
      + "DATAPERC80=1594633140.76 DATAPERC90=1594633142.88 "
      + "DATAREQUEST=1594633123.01 DATARESPONSE=1594633123.64 DIDTIMEOUT=0 "
      + "ENDPOINTLOCAL=localhost:127.0.0.1:46222 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:29849 "
      + "ENDPOINTREMOTE=jjsvldkkjd3lxy6gljy6xmhrn5mnirzgj2mrftrx2bf3n4bbx53fxza"
      + "d.onion:0.0.0.0:8080 FILESIZE=5242880 HOSTNAMELOCAL=op-nl-test1 "
      + "HOSTNAMEREMOTE=op-nl-test1 LAUNCH=1594633119.06 "
      + "NEGOTIATE=1594633118.41 PARTIAL10240=1594633123.80 "
      + "PARTIAL102400=1594633124.11 PARTIAL1048576=1594633127.56 "
      + "PARTIAL20480=1594633123.85 PARTIAL204800=1594633124.26 "
      + "PARTIAL2097152=1594633132.20 PARTIAL51200=1594633123.96 "
      + "PARTIAL512000=1594633125.50 PARTIAL5242880=1594633145.46 "
      + "PATH=$65888719E2F619E6198F1045A93AF0176C05354D,"
      + "$3043C1A6DF23AFEDC8FD3C0671FADCEDFF6D3429,"
      + "$8E5F4EE45E0631A60E59CAA42E1464FD7120459D QUANTILE=0.8 "
      + "READBYTES=5242990 REQUEST=1594633118.42 RESPONSE=1594633123.01 "
      + "SOCKET=1594633118.41 SOURCE=op-nl-test1 SOURCEADDRESS=unknown "
      + "START=1594633118.41 TIMEOUT=1500 USED_AT=1594633145.46 USED_BY=1498 "
      + "WRITEBYTES=2174";

  private final String torperfResultStream156
      = "CONNECT=1594633539.83 DATACOMPLETE=0.0 DATAREQUEST=0.0 "
      + "DATARESPONSE=0.0 DIDTIMEOUT=1 ENDPOINTLOCAL=localhost:127.0.0.1:46246 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:29849 "
      + "ENDPOINTREMOTE=jjsvldkkjd3lxy6gljy6xmhrn5mnirzgj2mrftrx2bf3n4bbx53fxza"
      + "d.onion:0.0.0.0:8080 ERRORCODE=TOR/TIMEOUT FILESIZE=5242880 "
      + "HOSTNAMELOCAL=op-nl-test1 HOSTNAMEREMOTE=(null) "
      + "NEGOTIATE=1594633539.83 READBYTES=0 REQUEST=1594633539.83 "
      + "RESPONSE=0.0 SOCKET=1594633539.83 SOURCE=op-nl-test1 "
      + "SOURCEADDRESS=unknown START=1594633539.83 USED_AT=1594633539.83 "
      + "USED_BY=1510 WRITEBYTES=0";

  @Test
  public void testAsTorperfResultsVersion3() throws IOException,
      DescriptorParseException {
    List<String> expectedTorperfResults = new ArrayList<>();
    expectedTorperfResults.add(torperfResultStream155);
    expectedTorperfResults.add(torperfResultStream156);
    URL resouce = getClass().getClassLoader().getResource(
        "onionperf/2020-07-13.op-nl-test1.onionperf.analysis.json.xz");
    assertNotNull(resouce);
    InputStream compressedInputStream = resouce.openStream();
    assertNotNull(compressedInputStream);
    byte[] rawDescriptorBytes = IOUtils.toByteArray(compressedInputStream);
    OnionPerfAnalysisConverter onionPerfAnalysisConverter
        = new OnionPerfAnalysisConverter(rawDescriptorBytes, null);
    for (Descriptor descriptor
        : onionPerfAnalysisConverter.asTorperfResults()) {
      assertTrue(descriptor instanceof TorperfResult);
      String formattedTorperfResult
          = new String(descriptor.getRawDescriptorBytes()).trim();
      assertNotNull(formattedTorperfResult);
      String expectedTorperfResult = expectedTorperfResults.remove(0);
      assertEquals(expectedTorperfResult, formattedTorperfResult);
    }
    assertTrue(expectedTorperfResults.isEmpty());
  }
}

