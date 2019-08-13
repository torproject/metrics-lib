/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.SnowflakeStats;

import org.hamcrest.Matchers;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.time.Duration;
import java.time.LocalDateTime;

public class SnowflakeStatsImplTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  /**
   * Example from example_metrics.log attached to #29461.
   */
  private static final String[] exampleMetricsLog = new String[] {
      "snowflake-stats-end 2019-08-07 19:52:11 (86400 s)",
      "snowflake-ips VN=5,NL=26,AU=30,GT=2,NO=5,EG=3,NI=1,AT=22,FR=42,CA=44,"
          + "ZA=3,PL=20,RU=10,HR=1,CN=1,RO=4,??=7,TH=7,UA=5,DZ=5,HU=5,CH=15,"
          + "AE=1,PH=6,RS=3,BR=20,IT=8,KR=13,HK=7,GR=5,GB=41,DK=4,CZ=7,IE=4,"
          + "PT=7,TR=2,NP=2,BA=1,BE=2,IN=45,SE=23,CL=3,IL=3,FI=7,MX=6,CO=1,"
          + "PK=4,ID=9,IR=7,JO=2,CR=2,US=265,DE=92,LV=1,MY=8,AR=5,NZ=10,BG=2,"
          + "UY=1,TW=5,SI=3,LU=2,GE=2,BN=1,JP=15,ES=9,SG=7,EC=1",
      "snowflake-ips-total 937",
      "snowflake-idle-count 660976",
      "client-denied-count 0",
      "client-snowflake-match-count 864" };

  @Test
  public void testExampleMetricsLog() throws DescriptorParseException {
    SnowflakeStats snowflakeStats = new SnowflakeStatsImpl(
        new TestDescriptorBuilder(exampleMetricsLog).build(), null);
    assertEquals(LocalDateTime.of(2019, 8, 7, 19, 52, 11),
        snowflakeStats.snowflakeStatsEnd());
    assertEquals(Duration.ofDays(1L),
        snowflakeStats.snowflakeStatsIntervalLength());
    assertTrue(snowflakeStats.snowflakeIps().isPresent());
    assertEquals(68, snowflakeStats.snowflakeIps().get().size());
    assertTrue(snowflakeStats.snowflakeIpsTotal().isPresent());
    assertEquals((Long) 937L, snowflakeStats.snowflakeIpsTotal().get());
    assertTrue(snowflakeStats.snowflakeIdleCount().isPresent());
    assertEquals((Long) 660976L, snowflakeStats.snowflakeIdleCount().get());
    assertTrue(snowflakeStats.clientDeniedCount().isPresent());
    assertEquals((Long) 0L, snowflakeStats.clientDeniedCount().get());
    assertTrue(snowflakeStats.clientSnowflakeMatchCount().isPresent());
    assertEquals((Long) 864L, snowflakeStats.clientSnowflakeMatchCount().get());
  }

  @Test
  public void testMinimalSnowflakeStats() throws DescriptorParseException {
    SnowflakeStats snowflakeStats = new SnowflakeStatsImpl(
        new TestDescriptorBuilder(exampleMetricsLog[0]).build(), null);
    assertEquals(LocalDateTime.of(2019, 8, 7, 19, 52, 11),
        snowflakeStats.snowflakeStatsEnd());
    assertEquals(Duration.ofDays(1L),
        snowflakeStats.snowflakeStatsIntervalLength());
    assertFalse(snowflakeStats.snowflakeIps().isPresent());
    assertFalse(snowflakeStats.snowflakeIpsTotal().isPresent());
    assertFalse(snowflakeStats.snowflakeIdleCount().isPresent());
    assertFalse(snowflakeStats.clientDeniedCount().isPresent());
    assertFalse(snowflakeStats.clientSnowflakeMatchCount().isPresent());
  }

  @Test
  public void testEmptyLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Blank lines are not allowed."));
    new SnowflakeStatsImpl(new TestDescriptorBuilder(exampleMetricsLog)
        .appendLines("")
        .build(), null);
  }

  @Test
  public void testDuplicateLine() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "must be contained at most once."));
    new SnowflakeStatsImpl(new TestDescriptorBuilder(
        exampleMetricsLog[0], exampleMetricsLog[1], exampleMetricsLog[1])
        .build(), null);
  }

  @Test
  public void testEmptyList() throws DescriptorParseException {
    SnowflakeStats snowflakeStats = new SnowflakeStatsImpl(
        new TestDescriptorBuilder(exampleMetricsLog[0], "snowflake-ips ")
        .build(), null);
    assertEquals(LocalDateTime.of(2019, 8, 7, 19, 52, 11),
        snowflakeStats.snowflakeStatsEnd());
    assertEquals(Duration.ofDays(1L),
        snowflakeStats.snowflakeStatsIntervalLength());
    assertTrue(snowflakeStats.snowflakeIps().isPresent());
    assertTrue(snowflakeStats.snowflakeIps().get().isEmpty());
  }

  @Test
  public void testNoValue() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "does not contain a long value at index 1."));
    new SnowflakeStatsImpl(new TestDescriptorBuilder(
        exampleMetricsLog[0], "snowflake-ips-total").build(), null);
  }

  @Test
  public void testNotANumber() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Unable to parse long value"));
    new SnowflakeStatsImpl(new TestDescriptorBuilder(
        exampleMetricsLog[0], "snowflake-ips-total NaN").build(), null);
  }

  @Test
  public void testNonPositiveIntervalLength() throws DescriptorParseException {
    this.thrown.expect(DescriptorParseException.class);
    this.thrown.expectMessage(Matchers.containsString(
        "Duration must be positive"));
    new SnowflakeStatsImpl(new TestDescriptorBuilder(
        "snowflake-stats-end 2019-08-07 19:52:11 (0 s)").build(), null);
  }
}

