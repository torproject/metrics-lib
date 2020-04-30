/* Copyright 2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.onionperf;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Builder that accepts key-value pairs and produces a single line in the
 * Torperf results format.
 */
public class TorperfResultsBuilder {

  /**
   * Key-value pairs to be formatted as Torperf results line.
   */
  private final SortedMap<String, String> keyValuePairs = new TreeMap<>();

  /**
   * Add a string value, unless it is {@code null}.
   *
   * @param key Key
   * @param stringValue String value
   */
  void addString(String key, String stringValue) {
    if (null != stringValue) {
      this.keyValuePairs.put(key, stringValue);
    }
  }

  /**
   * Add an int value, unless it is {@code null}.
   *
   * @param key Key.
   * @param integerValue Int value.
   */
  void addInteger(String key, Integer integerValue) {
    if (null != integerValue) {
      keyValuePairs.put(key, String.valueOf(integerValue));
    }
  }

  /**
   * Add a double value, unless it is {@code null}.
   *
   * @param key Key.
   * @param doubleValue Double value.
   */
  void addDouble(String key, Double doubleValue) {
    if (null != doubleValue) {
      keyValuePairs.put(key, String.valueOf(doubleValue));
    }
  }

  /**
   * Add a timestamp value as the sum of two double values, formatted as seconds
   * since the epoch with two decimal places, unless the first summand is
   * {@code null}.
   *
   * @param key Key.
   * @param unixTsStart First summand representing seconds since the epoch.
   * @param elapsedSeconds Second summand representing seconds elapsed since the
   *     first summand.
   */
  void addTimestamp(String key, Double unixTsStart, Double elapsedSeconds) {
    if (null != unixTsStart) {
      if (null != elapsedSeconds) {
        keyValuePairs.put(key, String.format("%.2f",
            unixTsStart + elapsedSeconds));
      } else {
        keyValuePairs.put(key, String.format("%.2f", unixTsStart));
      }
    }
  }

  /**
   * Build the Torperf results line by putting together all key-value pairs as
   * {@code "key=value"}, separated by spaces, prefixed by an annotation line
   * {@code "@type torperf 1.1"}.
   *
   * @return Torperf results line using the same format as OnionPerf would
   *     write it.
   */
  String build() {
    StringBuilder result = new StringBuilder();
    result.append("@type torperf 1.1\r\n");
    List<String> torperfResultsParts = new ArrayList<>();
    for (Map.Entry<String, String> keyValuePairsEntry
        : this.keyValuePairs.entrySet()) {
      torperfResultsParts.add(String.format("%s=%s",
          keyValuePairsEntry.getKey(), keyValuePairsEntry.getValue()));
    }
    result.append(String.join(" ", torperfResultsParts)).append("\r\n");
    return result.toString();
  }
}

