/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;

import org.junit.Test;

import java.util.List;

public class TorperfResultImplTest {

  @Test
  public void testAnnotatedInput() throws Exception {
    TorperfResultImpl result = (TorperfResultImpl)
        (TorperfResultImpl.parseTorperfResults((torperfAnnotation + input)
        .getBytes("US-ASCII"), null).get(0));
    assertEquals("Expected one annotation.", 1,
        result.getAnnotations().size());
    assertEquals(torperfAnnotation.substring(0, 17),
        result.getAnnotations().get(0));
    int count = 0;
    for (Long l: result.getDataPercentiles().values()) {
      assertNotNull(l);
      assertEquals(l.longValue(), deciles[count++]);
    }
  }

  @Test
  public void testPartiallyAnnotatedInput() throws Exception {
    byte[] asciiBytes = (torperfAnnotation
        + input + input + input).getBytes("US-ASCII");
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        asciiBytes, null);
    assertEquals("Expected one annotation.", 1,
        ((TorperfResultImpl)(result.get(0))).getAnnotations().size());
    assertEquals(3, result.size());
    assertEquals("Expected zero annotations.", 0,
        ((TorperfResultImpl)(result.get(1))).getAnnotations().size());
    assertEquals("Expected zero annotations.", 0,
        ((TorperfResultImpl)(result.get(2))).getAnnotations().size());
  }

  @Test
  public void testAllAnnotatedInput() throws Exception {
    byte[] asciiBytes = (torperfAnnotation + input
        + torperfAnnotation + input
        + torperfAnnotation + input).getBytes("US-ASCII");
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        asciiBytes, null);
    assertEquals("Expected one annotation.", 1,
        ((TorperfResultImpl)(result.get(0))).getAnnotations().size());
    assertEquals(3, result.size());
    assertEquals("Expected one annotation.", 1,
        ((TorperfResultImpl)(result.get(1))).getAnnotations().size());
    assertEquals("Expected one annotation.", 1,
        ((TorperfResultImpl)(result.get(2))).getAnnotations().size());
  }

  private static long[] deciles = new long[] {
      1441065602980L, 1441065603030L, 1441065603090L, 1441065603120L,
      1441065603230L, 1441065603250L, 1441065603310L, 1441065603370L,
      1441065603370L };

  private static final String torperfAnnotation = "@type torperf 1.0\n";

  private static final String input =
      "BUILDTIMES=0.872834920883,1.09103679657,1.49180984497 "
      + "CIRC_ID=1228 CONNECT=1441065601.86 DATACOMPLETE=1441065603.39 "
      + "DATAPERC10=1441065602.98 DATAPERC20=1441065603.03 "
      + "DATAPERC30=1441065603.09 DATAPERC40=1441065603.12 "
      + "DATAPERC50=1441065603.23 DATAPERC60=1441065603.25 "
      + "DATAPERC70=1441065603.31 DATAPERC80=1441065603.37 "
      + "DATAPERC90=1441065603.37 DATAREQUEST=1441065602.38 "
      + "DATARESPONSE=1441065602.84 DIDTIMEOUT=0 FILESIZE=51200 "
      + "LAUNCH=1441065361.30 NEGOTIATE=1441065601.86 "
      + "PATH=$C4C9C332D25B3546BEF4E1250CF410E97EF996E6,"
      + "$C43FA6474A9F071E9120DF63ED6EB8FDBA105234,"
      + "$7C0AA4E3B73E407E9F5FEB1912F8BE26D8AA124D QUANTILE=0.800000 "
      + "READBYTES=51416 REQUEST=1441065601.86 RESPONSE=1441065602.38 "
      + "SOCKET=1441065601.86 SOURCE=moria START=1441065601.86 "
      + "TIMEOUT=1500 USED_AT=1441065603.40 USED_BY=2475 WRITEBYTES=75\n";

  @Test
  public void testDatapercNonNumeric() throws Exception {
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        ("DATAPERMILLE=2.0 " + input).getBytes(), null);
    assertEquals(1, result.size());
    TorperfResultImpl torperfResult = (TorperfResultImpl) result.get(0);
    assertEquals(1, torperfResult.getUnrecognizedKeys().size());
    assertEquals("DATAPERMILLE",
        torperfResult.getUnrecognizedKeys().firstKey());
  }

  private static final String input2 =
      "BUILDTIMES=0.490000009537,0.610000133514,0.75 CIRC_ID=8522 "
      + "CONNECT=1493397365.14 DATACOMPLETE=1493397368.13 "
      + "DATAPERC0=1493397367.67 DATAPERC10=1493397367.81 "
      + "DATAPERC100=1493397368.13 DATAPERC20=1493397367.87 "
      + "DATAPERC30=1493397367.87 DATAPERC40=1493397367.90 "
      + "DATAPERC50=1493397367.91 DATAPERC60=1493397367.97 "
      + "DATAPERC70=1493397367.97 DATAPERC80=1493397367.99 "
      + "DATAPERC90=1493397367.99 DATAREQUEST=1493397367.33 "
      + "DATARESPONSE=1493397367.67 DIDTIMEOUT=0 "
      + "ENDPOINTLOCAL=localhost:127.0.0.1:42436 "
      + "ENDPOINTPROXY=localhost:127.0.0.1:52265 "
      + "ENDPOINTREMOTE=4jocm7xwo4ltrvzp.onion:0.0.0.0:80 FILESIZE=51200 "
      + "HOSTNAMELOCAL=op-us HOSTNAMEREMOTE=op-us LAUNCH=1493396168.1 "
      + "NEGOTIATE=1493397365.14 "
      + "PATH=$F69BED36177ED727706512BA6A97755025EEA0FB,"
      + "$91D23D8A539B83D2FB56AA67ECD4D75CC093AC55,"
      + "$4DD902046E7155BBE79C34EE6D53BF7408B98CE4 QUANTILE=0.8 "
      + "READBYTES=51269 REQUEST=1493397365.14 RESPONSE=1493397367.32 "
      + "SOCKET=1493397365.14 SOURCE=op-us SOURCEADDRESS=199.119.112.144 "
      + "START=1493397365.14 TIMEOUT=1500 USED_AT=1493397368.14 "
      + "USED_BY=17429 WRITEBYTES=54";

  @Test
  public void testEndpointsHostnamesSourceAddress()
      throws DescriptorParseException {
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        input2.getBytes(), null);
    assertEquals(1, result.size());
    TorperfResultImpl torperfResult = (TorperfResultImpl) result.get(0);
    assertNull(torperfResult.getUnrecognizedKeys());
    assertEquals("localhost:127.0.0.1:42436", torperfResult.getEndpointLocal());
    assertEquals("localhost:127.0.0.1:52265", torperfResult.getEndpointProxy());
    assertEquals("4jocm7xwo4ltrvzp.onion:0.0.0.0:80",
        torperfResult.getEndpointRemote());
    assertEquals("op-us", torperfResult.getHostnameLocal());
    assertEquals("op-us", torperfResult.getHostnameRemote());
    assertEquals("199.119.112.144", torperfResult.getSourceAddress());
  }
}

