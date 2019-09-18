/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.BridgedbMetrics;
import org.torproject.descriptor.DescriptorParseException;

import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Duration;
import java.time.LocalDateTime;

public class BridgedbMetricsImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /**
   * Example taken from BridgeDB metrics from 2019-09-17.
   */
  private static final String[] exampleBridgedbMetricsLog = new String[] {
      "bridgedb-metrics-end 2019-09-17 00:33:44 (86400 s)",
      "bridgedb-metrics-version 1",
      "bridgedb-metric-count https.obfs3.ru.success.none 10",
      "bridgedb-metric-count https.obfs3.sk.success.none 10",
      "bridgedb-metric-count https.fte.de.fail.none 10" };

  @Test
  public void testExampleMetricsLog() throws DescriptorParseException {
    BridgedbMetrics bridgedbMetrics = new BridgedbMetricsImpl(
        new TestDescriptorBuilder(exampleBridgedbMetricsLog).build(), null);
    assertEquals(LocalDateTime.of(2019, 9, 17, 0, 33, 44),
        bridgedbMetrics.bridgedbMetricsEnd());
    assertEquals(Duration.ofDays(1L),
        bridgedbMetrics.bridgedbMetricsIntervalLength());
    assertEquals("1", bridgedbMetrics.bridgedbMetricsVersion());
    assertTrue(bridgedbMetrics.bridgedbMetricCounts().isPresent());
    assertEquals(3, bridgedbMetrics.bridgedbMetricCounts().get().size());
    assertEquals((Long) 10L, bridgedbMetrics.bridgedbMetricCounts().get()
        .get("https.obfs3.ru.success.none"));
    assertEquals((Long) 10L, bridgedbMetrics.bridgedbMetricCounts().get()
        .get("https.obfs3.sk.success.none"));
    assertEquals((Long) 10L, bridgedbMetrics.bridgedbMetricCounts().get()
        .get("https.fte.de.fail.none"));
  }

  @Test
  public void testMinimalBridgedbMetrics() throws DescriptorParseException {
    BridgedbMetrics bridgedbMetrics = new BridgedbMetricsImpl(
        new TestDescriptorBuilder(exampleBridgedbMetricsLog[0],
            exampleBridgedbMetricsLog[1]).build(), null);
    assertEquals(LocalDateTime.of(2019, 9, 17, 0, 33, 44),
        bridgedbMetrics.bridgedbMetricsEnd());
    assertEquals(Duration.ofDays(1L),
        bridgedbMetrics.bridgedbMetricsIntervalLength());
    assertEquals("1", bridgedbMetrics.bridgedbMetricsVersion());
    assertFalse(bridgedbMetrics.bridgedbMetricCounts().isPresent());
  }

  @Test
  public void testEmptyLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Blank lines are not allowed."));
    new BridgedbMetricsImpl(new TestDescriptorBuilder(exampleBridgedbMetricsLog)
        .appendLines("")
        .build(), null);
  }

  @Test
  public void testDuplicateLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "must be contained exactly once."));
    new BridgedbMetricsImpl(new TestDescriptorBuilder(
        exampleBridgedbMetricsLog[0], exampleBridgedbMetricsLog[1],
        exampleBridgedbMetricsLog[1]).build(), null);
  }

  @Test
  public void testDuplicateKey() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString("Duplicate key"));
    new BridgedbMetricsImpl(new TestDescriptorBuilder(
        exampleBridgedbMetricsLog[0], exampleBridgedbMetricsLog[1],
        exampleBridgedbMetricsLog[2], exampleBridgedbMetricsLog[2])
        .build(), null);
  }

  @Test
  public void testNoValue() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Unable to parse long value '10-ish' in line"));
    new BridgedbMetricsImpl(new TestDescriptorBuilder(
        exampleBridgedbMetricsLog[0], exampleBridgedbMetricsLog[1],
        exampleBridgedbMetricsLog[2] + "-ish").build(), null);
  }

  @Test
  public void testNonPositiveIntervalLength() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Duration must be positive"));
    new BridgedbMetricsImpl(new TestDescriptorBuilder(
        "bridgedb-metrics-end 2019-09-17 00:33:44 (0 s)",
        exampleBridgedbMetricsLog[1]).build(), null);
  }
}

