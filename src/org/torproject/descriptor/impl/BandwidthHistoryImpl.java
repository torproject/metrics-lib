/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.SortedMap;
import java.util.TreeMap;

import org.torproject.descriptor.BandwidthHistory;

public class BandwidthHistoryImpl implements BandwidthHistory {

  protected BandwidthHistoryImpl(String line, String lineNoOpt,
      String[] partsNoOpt) throws DescriptorParseException {
    boolean isValid = false;
    if (partsNoOpt.length >= 5) {
      try {
        this.line = line;
        if (lineNoOpt.startsWith("read-history  ")) {
          lineNoOpt = "read-history "
              + lineNoOpt.substring("read-history  ".length());
          partsNoOpt = lineNoOpt.split(" ");
        }
        this.historyEndMillis = ParseHelper.parseTimestampAtIndex(line,
            partsNoOpt, 1, 2);
        if (partsNoOpt[3].startsWith("(") &&
            partsNoOpt[4].equals("s)")) {
          this.intervalLength = Long.parseLong(partsNoOpt[3].
              substring(1));
          if (this.intervalLength <= 0L) {
            throw new DescriptorParseException("Only positive interval "
                + "lengths are allowed in line '" + line + "'.");
          }
          if (partsNoOpt.length > 6) {
            /* Invalid line, handle below. */
          } else if (partsNoOpt.length == 5) {
            /* No bandwidth values to parse. */
            isValid = true;
          } else {
            long endMillis = this.historyEndMillis;
            String[] values = partsNoOpt[5].split(",", -1);
            for (int i = values.length - 1; i >= 0; i--) {
              long bandwidthValue = Long.parseLong(values[i]);
              if (bandwidthValue < 0L) {
                throw new DescriptorParseException("Negative bandwidth "
                    + "values are not allowed in line '" + line + "'.");
              }
              this.bandwidthValues.put(endMillis, bandwidthValue);
              endMillis -= this.intervalLength * 1000L;
            }
            isValid = true;
          }
        }
      } catch (NumberFormatException e) {
        /* Handle below. */
      }
    }
    if (!isValid) {
      throw new DescriptorParseException("Invalid bandwidth-history line "
          + "'" + line + "'.");
    }
  }

  private String line;
  public String getLine() {
    return this.line;
  }

  private long historyEndMillis;
  public long getHistoryEndMillis() {
    return this.historyEndMillis;
  }

  private long intervalLength;
  public long getIntervalLength() {
    return this.intervalLength;
  }

  private SortedMap<Long, Long> bandwidthValues =
      new TreeMap<Long, Long>();
  public SortedMap<Long, Long> getBandwidthValues() {
    return new TreeMap<Long, Long>(this.bandwidthValues);
  }
}

