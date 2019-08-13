/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.SnowflakeStats;

import java.io.File;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;
import java.util.SortedMap;

public class SnowflakeStatsImpl extends DescriptorImpl
    implements SnowflakeStats {

  private static final Set<Key> atMostOnce = EnumSet.of(
      Key.SNOWFLAKE_IPS, Key.SNOWFLAKE_IPS_TOTAL, Key.SNOWFLAKE_IDLE_COUNT,
      Key.CLIENT_DENIED_COUNT, Key.CLIENT_SNOWFLAKE_MATCH_COUNT);

  private static final Set<Key> exactlyOnce = EnumSet.of(
      Key.SNOWFLAKE_STATS_END);

  SnowflakeStatsImpl(byte[] rawDescriptorBytes, int[] offsetAndLength,
      File descriptorFile) throws DescriptorParseException {
    super(rawDescriptorBytes, offsetAndLength, descriptorFile, false);
    this.parseDescriptorBytes();
    this.checkExactlyOnceKeys(exactlyOnce);
    this.checkAtMostOnceKeys(atMostOnce);
    this.checkFirstKey(Key.SNOWFLAKE_STATS_END);
    this.clearParsedKeys();
  }

  SnowflakeStatsImpl(byte[] rawDescriptorBytes, File descriptorFile)
      throws DescriptorParseException {
    this(rawDescriptorBytes, new int[] { 0, rawDescriptorBytes.length },
        descriptorFile);
  }

  private void parseDescriptorBytes() throws DescriptorParseException {
    Scanner scanner = this.newScanner().useDelimiter(NL);
    while (scanner.hasNext()) {
      String line = scanner.next();
      if (line.startsWith("@")) {
        continue;
      }
      String[] parts = line.split("[ \t]+");
      Key key = Key.get(parts[0]);
      switch (key) {
        case SNOWFLAKE_STATS_END:
          this.parseSnowflakeStatsEnd(line, parts);
          break;
        case SNOWFLAKE_IPS:
          this.parseSnowflakeIps(line, parts);
          break;
        case SNOWFLAKE_IPS_TOTAL:
          this.parseSnowflakeIpsTotal(line, parts);
          break;
        case SNOWFLAKE_IDLE_COUNT:
          this.parseSnowflakeIdleCount(line, parts);
          break;
        case CLIENT_DENIED_COUNT:
          this.parseClientDeniedCount(line, parts);
          break;
        case CLIENT_SNOWFLAKE_MATCH_COUNT:
          this.parseClientSnowflakeMatchCount(line, parts);
          break;
        case INVALID:
        default:
          ParseHelper.parseKeyword(line, parts[0]);
          if (this.unrecognizedLines == null) {
            this.unrecognizedLines = new ArrayList<>();
          }
          this.unrecognizedLines.add(line);
      }
    }
  }

  private void parseSnowflakeStatsEnd(String line, String[] parts)
      throws DescriptorParseException {
    if (parts.length < 5 || parts[3].length() < 2 || !parts[3].startsWith("(")
        || !parts[4].equals("s)")) {
      throw new DescriptorParseException("Illegal line '" + line + "'.");
    }
    this.snowflakeStatsEnd = ParseHelper.parseLocalDateTime(line, parts,
        1, 2);
    this.snowflakeStatsIntervalLength = ParseHelper.parseDuration(line,
        parts[3].substring(1));
  }

  private void parseSnowflakeIps(String line, String[] parts)
      throws DescriptorParseException {
    this.snowflakeIps = ParseHelper.parseCommaSeparatedKeyLongValueList(line,
        parts, 1, 2);
  }

  private void parseSnowflakeIpsTotal(String line, String[] parts)
      throws DescriptorParseException {
    this.snowflakeIpsTotal = parseLong(line, parts, 1);
  }

  private void parseSnowflakeIdleCount(String line, String[] parts)
      throws DescriptorParseException {
    this.snowflakeIdleCount = parseLong(line, parts, 1);
  }

  private void parseClientDeniedCount(String line, String[] parts)
      throws DescriptorParseException {
    this.clientDeniedCount = parseLong(line, parts, 1);
  }

  private void parseClientSnowflakeMatchCount(String line, String[] parts)
      throws DescriptorParseException {
    this.clientSnowflakeMatchCount = parseLong(line, parts, 1);
  }

  private static Long parseLong(String line, String[] parts, int index)
      throws DescriptorParseException {
    if (index >= parts.length) {
      throw new DescriptorParseException(String.format(
          "Line '%s' does not contain a long value at index %d.", line, index));
    }
    try {
      return Long.parseLong(parts[index]);
    } catch (NumberFormatException e) {
      throw new DescriptorParseException(String.format(
          "Unable to parse long value '%s' in line '%s'.", parts[index], line));
    }
  }

  private LocalDateTime snowflakeStatsEnd;

  @Override
  public LocalDateTime snowflakeStatsEnd() {
    return this.snowflakeStatsEnd;
  }

  private Duration snowflakeStatsIntervalLength;

  @Override
  public Duration snowflakeStatsIntervalLength() {
    return this.snowflakeStatsIntervalLength;
  }

  private SortedMap<String, Long> snowflakeIps;

  @Override
  public Optional<SortedMap<String, Long>> snowflakeIps() {
    return Optional.ofNullable(this.snowflakeIps);
  }

  private Long snowflakeIpsTotal;

  @Override
  public Optional<Long> snowflakeIpsTotal() {
    return Optional.ofNullable(this.snowflakeIpsTotal);
  }

  private Long snowflakeIdleCount;

  @Override
  public Optional<Long> snowflakeIdleCount() {
    return Optional.ofNullable(this.snowflakeIdleCount);
  }

  private Long clientDeniedCount;

  @Override
  public Optional<Long> clientDeniedCount() {
    return Optional.ofNullable(this.clientDeniedCount);
  }

  private Long clientSnowflakeMatchCount;

  @Override
  public Optional<Long> clientSnowflakeMatchCount() {
    return Optional.ofNullable(this.clientSnowflakeMatchCount);
  }
}

