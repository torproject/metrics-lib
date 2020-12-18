/* Copyright 2019--2020 The Tor Project
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
      "snowflake-ips-standalone 3",
      "snowflake-ips-badge 0",
      "snowflake-ips-webext 4118",
      "snowflake-idle-count 660976",
      "client-denied-count 0",
      "client-snowflake-match-count 864" };

  /**
   * Snowflake statistics written on 2020-12-16 at 19:24:38 as obtained from
   * CollecTor.
   */
  private static final String[] snowflakeStats20201216192438 = new String[] {
      "@type snowflake-stats 1.0",
      "snowflake-stats-end 2020-12-16 19:24:38 (86400 s)",
      "snowflake-ips US=1716,SE=109,PH=97,EC=5,FO=1,AU=121,SA=12,PK=8,IR=12,"
          + "GF=2,UZ=1,BY=12,BE=39,MT=2,BA=2,SC=1,MM=3,FR=272,PS=7,LT=12,"
          + "NL=209,CY=4,TW=26,GA=4,IL=25,MX=38,HU=35,HR=21,AE=6,PY=5,PT=50,"
          + "FI=48,RO=116,DE=877,MY=27,CA=223,IQ=1,CZ=46,SI=7,RS=14,KN=3,JO=2,"
          + "TN=3,LB=2,PE=6,ID=28,MK=2,AT=70,MV=1,BR=149,TR=19,JP=513,CH=151,"
          + "NZ=36,VN=18,MD=2,GR=56,UA=33,AZ=3,CN=74,RU=113,LV=23,EE=10,TH=63,"
          + "BG=10,??=15,HK=22,CR=3,SD=2,GB=372,DK=37,BD=5,ZA=22,LU=24,KR=26,"
          + "LK=3,IS=3,PR=1,MO=1,PL=165,NO=49,CL=15,IE=24,KE=1,MA=2,GT=1,ES=74,"
          + "EG=16,PA=3,IN=142,CO=5,GI=1,DZ=12,KZ=1,AR=24,UY=3,NP=8,SN=2,SG=45,"
          + "TZ=1,SK=20,TG=8,BZ=5,IT=172,BF=2",
      "snowflake-ips-total 6943",
      "snowflake-ips-standalone 32",
      "snowflake-ips-badge 27",
      "snowflake-ips-webext 6882",
      "snowflake-idle-count 956568",
      "client-denied-count 640",
      "client-restricted-denied-count 640",
      "client-unrestricted-denied-count 0",
      "client-snowflake-match-count 11456",
      "snowflake-ips-nat-restricted 3140",
      "snowflake-ips-nat-unrestricted 29",
      "snowflake-ips-nat-unknown 3768" };

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
    assertTrue(snowflakeStats.snowflakeIpsStandalone().isPresent());
    assertEquals((Long) 3L, snowflakeStats.snowflakeIpsStandalone().get());
    assertTrue(snowflakeStats.snowflakeIpsBadge().isPresent());
    assertEquals((Long) 0L, snowflakeStats.snowflakeIpsBadge().get());
    assertTrue(snowflakeStats.snowflakeIpsWebext().isPresent());
    assertEquals((Long) 4118L, snowflakeStats.snowflakeIpsWebext().get());
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
    assertFalse(snowflakeStats.snowflakeIpsStandalone().isPresent());
    assertFalse(snowflakeStats.snowflakeIpsBadge().isPresent());
    assertFalse(snowflakeStats.snowflakeIpsWebext().isPresent());
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

  @Test
  public void testNatBasedSnowflakeLines() throws DescriptorParseException {
    SnowflakeStats snowflakeStats = new SnowflakeStatsImpl(
        new TestDescriptorBuilder(snowflakeStats20201216192438).build(), null);
    assertTrue(snowflakeStats.clientRestrictedDeniedCount().isPresent());
    assertEquals((Long) 640L,
        snowflakeStats.clientRestrictedDeniedCount().get());
    assertTrue(snowflakeStats.clientUnrestrictedDeniedCount().isPresent());
    assertEquals((Long) 0L,
        snowflakeStats.clientUnrestrictedDeniedCount().get());
    assertTrue(snowflakeStats.snowflakeIpsNatRestricted().isPresent());
    assertEquals((Long) 3140L,
        snowflakeStats.snowflakeIpsNatRestricted().get());
    assertTrue(snowflakeStats.snowflakeIpsNatUnrestricted().isPresent());
    assertEquals((Long) 29L,
        snowflakeStats.snowflakeIpsNatUnrestricted().get());
    assertTrue(snowflakeStats.snowflakeIpsNatUnknown().isPresent());
    assertEquals((Long) 3768L, snowflakeStats.snowflakeIpsNatUnknown().get());
  }
}

