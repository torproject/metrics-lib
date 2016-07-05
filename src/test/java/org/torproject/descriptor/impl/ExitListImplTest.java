/* Copyright 2015--2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExitListEntry;

public class ExitListImplTest {

  @Test()
  public void testAnnotatedInput() throws Exception {
    ExitListImpl result = new ExitListImpl((tordnselAnnotation + input)
        .getBytes("US-ASCII"), fileName, false);
    assertEquals("Expected one annotation.", 1,
        result.getAnnotations().size());
    assertEquals(tordnselAnnotation.substring(0, 18),
        result.getAnnotations().get(0));
    assertEquals(1441065722000L, result.getDownloadedMillis());
    assertTrue("Unrecognized lines: " + result.getUnrecognizedLines(),
        result.getUnrecognizedLines().isEmpty());
    assertEquals("Found: " + result.getExitListEntries(), 7,
        result.getExitListEntries().size());
    assertEquals("Found: " + result.getEntries(), 5,
        result.getEntries().size());
  }

  @Test()
  public void testMultipleOldExitAddresses() throws Exception {
    ExitListImpl result = new ExitListImpl(
        (tordnselAnnotation + multiExitAddressInput)
        .getBytes("US-ASCII"), fileName, false);
    assertTrue("Unrecognized lines: " + result.getUnrecognizedLines(),
        result.getUnrecognizedLines().isEmpty());
    assertEquals("Found: " + result.getExitListEntries(),
        3, result.getExitListEntries().size());
    Map<String, Long> testMap = new HashMap();
    testMap.put("81.7.17.171", 1441044592000L);
    testMap.put("81.7.17.172", 1441044652000L);
    testMap.put("81.7.17.173", 1441044712000L);
    for (ExitListEntry ele : result.getExitListEntries()) {
      Map<String, Long> map = ele.getExitAddresses();
      assertEquals("Found: " + map, 1, map.size());
      Map.Entry<String, Long> ea = map.entrySet().iterator().next();
      assertTrue("Map: " + testMap,
          testMap.keySet().contains(ea.getKey()));
      assertTrue("Map: " + testMap + " exitaddress: " + ea,
          testMap.values().contains(ea.getValue()));
      testMap.remove(ea.getKey());
    }
    assertTrue("Map: " + testMap, testMap.isEmpty());
  }

  @Test()
  public void testMultipleExitAddresses() throws Exception {
    ExitListImpl result = new ExitListImpl(
        (tordnselAnnotation + multiExitAddressInput)
        .getBytes("US-ASCII"), fileName, false);
    assertTrue("Unrecognized lines: " + result.getUnrecognizedLines(),
        result.getUnrecognizedLines().isEmpty());
    Map<String, Long> map = result.getEntries()
        .iterator().next().getExitAddresses();
    assertEquals("Found: " + map, 3, map.size());
    assertTrue("Map: " + map, map.containsKey("81.7.17.171"));
    assertTrue("Map: " + map, map.containsKey("81.7.17.172"));
    assertTrue("Map: " + map, map.containsKey("81.7.17.173"));
  }

  @Test(expected = DescriptorParseException.class)
  public void testInsufficientInput0() throws Exception {
    new ExitListImpl((tordnselAnnotation + insufficientInput[0])
        .getBytes("US-ASCII"), fileName, false);
  }

  @Test(expected = DescriptorParseException.class)
  public void testInsufficientInput1() throws Exception {
    new ExitListImpl((tordnselAnnotation + insufficientInput[1])
        .getBytes("US-ASCII"), fileName, false);
  }

  private static final String tordnselAnnotation = "@type tordnsel 1.0\n";
  private static final String fileName = "2015-09-01-00-02-02";
  private static final String[] insufficientInput = new String[] {
      "Downloaded 2015-09-01 00:02:02\n"
      + "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
      + "Published 2015-08-31 16:17:30\n"
      + "LastStatus 2015-08-31 17:03:18\n",
      "Downloaded 2015-09-01 00:02:02\n"
      + "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
      + "LastStatus 2015-08-31 17:03:18\n"
      + "ExitAddress 81.7.17.172 2015-08-31 18:10:52\n" };

  private static final String multiExitAddressInput =
      "Downloaded 2015-09-01 00:02:02\n"
      + "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
      + "Published 2015-08-31 16:17:30\n"
      + "LastStatus 2015-08-31 17:03:18\n"
      + "ExitAddress 81.7.17.171 2015-08-31 18:09:52\n"
      + "ExitAddress 81.7.17.172 2015-08-31 18:10:52\n"
      + "ExitAddress 81.7.17.173 2015-08-31 18:11:52\n";
  private static final String input = "Downloaded 2015-09-01 00:02:02\n"
      + "ExitNode 0011BD2485AD45D984EC4159C88FC066E5E3300E\n"
      + "Published 2015-08-31 16:17:30\n"
      + "LastStatus 2015-08-31 17:03:18\n"
      + "ExitAddress 162.247.72.201 2015-08-31 17:09:23\n"
      + "ExitNode 0098C475875ABC4AA864738B1D1079F711C38287\n"
      + "Published 2015-08-31 13:59:24\n"
      + "LastStatus 2015-08-31 15:03:20\n"
      + "ExitAddress 162.248.160.151 2015-08-31 15:07:27\n"
      + "ExitNode 00C4B4731658D3B4987132A3F77100CFCB190D97\n"
      + "Published 2015-08-31 17:47:52\n"
      + "LastStatus 2015-08-31 18:03:17\n"
      + "ExitAddress 81.7.17.171 2015-08-31 18:09:52\n"
      + "ExitAddress 81.7.17.172 2015-08-31 18:10:52\n"
      + "ExitAddress 81.7.17.173 2015-08-31 18:11:52\n"
      + "ExitNode 00F2D93EBAF2F51D6EE4DCB0F37D91D72F824B16\n"
      + "Published 2015-08-31 14:39:05\n"
      + "LastStatus 2015-08-31 16:02:18\n"
      + "ExitAddress 23.239.18.57 2015-08-31 16:06:07\n"
      + "ExitNode 011B1D1E876B2C835D01FB9D407F2E00B28077F6\n"
      + "Published 2015-08-31 05:14:35\n"
      + "LastStatus 2015-08-31 06:03:29\n"
      + "ExitAddress 104.131.51.150 2015-08-31 06:04:07\n";
}

