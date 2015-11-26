/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;
import org.torproject.descriptor.Descriptor;

public class TorperfResultImplTest {

  @Test()
  public void testAnnotatedInput() throws Exception{
    TorperfResultImpl result = (TorperfResultImpl)
        (TorperfResultImpl.parseTorperfResults((torperfAnnotation + input)
        .getBytes("US-ASCII"), false).get(0));
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

  @Test()
  public void testPartiallyAnnotatedInput() throws Exception{
    byte[] asciiBytes = (torperfAnnotation
        + input + input + input).getBytes("US-ASCII");
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        asciiBytes, false);
    assertEquals("Expected one annotation.", 1,
        ((TorperfResultImpl)(result.get(0))).getAnnotations().size());
    assertEquals(3, result.size());
    assertEquals("Expected zero annotations.", 0,
        ((TorperfResultImpl)(result.get(1))).getAnnotations().size());
    assertEquals("Expected zero annotations.", 0,
        ((TorperfResultImpl)(result.get(2))).getAnnotations().size());
  }

  @Test()
  public void testAllAnnotatedInput() throws Exception{
    byte[] asciiBytes = (torperfAnnotation + input
        + torperfAnnotation + input
        + torperfAnnotation + input).getBytes("US-ASCII");
    List<Descriptor> result = TorperfResultImpl.parseTorperfResults(
        asciiBytes, false);
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
}

