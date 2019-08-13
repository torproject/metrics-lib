/* Copyright 2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.SortedMap;

/**
 * Contain aggregated information about snowflake proxies and snowflake clients.
 *
 * @since 2.7.0
 */
public interface SnowflakeStats extends Descriptor {

  /**
   * Return the end of the included measurement interval.
   *
   * @return End of the included measurement interval.
   * @since 2.7.0
   */
  LocalDateTime snowflakeStatsEnd();

  /**
   * Return the length of the included measurement interval.
   *
   * @return Length of the included measurement interval.
   * @since 2.7.0
   */
  Duration snowflakeStatsIntervalLength();

  /**
   * Return a list of mappings from two-letter country codes to the number of
   * unique IP addresses of snowflake proxies that have polled.
   *
   * @return List of mappings from two-letter country codes to the number of
   *     unique IP addresses of snowflake proxies that have polled.
   * @since 2.7.0
   */
  Optional<SortedMap<String, Long>> snowflakeIps();

  /**
   * Return a count of the total number of unique IP addresses of snowflake
   * proxies that have polled.
   *
   * @return Count of the total number of unique IP addresses of snowflake
   *     proxies that have polled.
   * @since 2.7.0
   */
  Optional<Long> snowflakeIpsTotal();

  /**
   * Return a count of the number of times a proxy has polled but received no
   * client offer, rounded up to the nearest multiple of 8.
   *
   * @return Count of the number of times a proxy has polled but received no
   *     client offer, rounded up to the nearest multiple of 8.
   * @since 2.7.0
   */
  Optional<Long> snowflakeIdleCount();

  /**
   * Return a count of the number of times a client has requested a proxy from
   * the broker but no proxies were available, rounded up to the nearest
   * multiple of 8.
   *
   * @return Count of the number of times a client has requested a proxy from
   *     the broker but no proxies were available, rounded up to the nearest
   *     multiple of 8.
   * @since 2.7.0
   */
  Optional<Long> clientDeniedCount();

  /**
   * Return a count of the number of times a client successfully received a
   * proxy from the broker, rounded up to the nearest multiple of 8.
   *
   * @return Count of the number of times a client successfully received a proxy
   *     from the broker, rounded up to the nearest multiple of 8.
   * @since 2.7.0
   */
  Optional<Long> clientSnowflakeMatchCount();
}

