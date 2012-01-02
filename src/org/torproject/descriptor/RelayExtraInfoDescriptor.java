/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;

public interface RelayExtraInfoDescriptor extends Descriptor {

  /* Return the relay's nickname. */
  public String getNickname();

  /* Return the relay's fingerprint. */
  public String getFingerprint();

  /* Return the publication time of this descriptor. */
  public long getPublishedMillis();

  /* Return the read history contained in this descriptor, or null if no
   * read history is contained. */
  public BandwidthHistory getReadHistory();

  /* Return the write history contained in this descriptor, or null if no
   * read history is contained. */
  public BandwidthHistory getWriteHistory();

  /* Return the SHA1 digest of the GeoIP database used by this relay, or
   * null if no GeoIP database digest is included. */
  public String getGeoipDbDigest();

  /* Return the end of the included directory request statistics interval,
   * or -1 if no directory request statistics are included. */
  public long getDirreqStatsEndMillis();

  /* Return the interval length of the included directory request
   * statistics, or -1 if no directory request statistics are included. */
  public long getDirreqStatsIntervalLength();

  /* Return statistics on unique IP addresses requesting v2 network
   * statuses with map keys being country codes and map values being
   * numbers of unique IP addresses rounded up to the nearest multiple of
   * 8, or null if no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV2Ips();

  /* Return statistics on unique IP addresses requesting v3 network status
   * consensuses with map keys being country codes and map values being
   * numbers of unique IP addresses rounded up to the nearest multiple of
   * 8, or null if no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV3Ips();

  /* Return statistics on directory requests for v2 network statuses with
   * map keys being country codes and map values being request numbers
   * rounded up to the nearest multiple of 8, or null if no such
   * statistics are included. */
  public SortedMap<String, Integer> getDirreqV2Reqs();

  /* Return statistics on directory requests for v3 network status
   * consensuses with map keys being country codes and map values being
   * request numbers rounded up to the nearest multiple of 8, or null if
   * no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV3Reqs();

  /* Return the share of requests for v2 network statuses that the
   * directory expects to receive from clients, or -1.0 if no such
   * statistics are included. */
  public double getDirreqV2Share();

  /* Return the share of requests for v3 network status consensuses that
   * the directory expects to receive from clients, or -1.0 if no such
   * statistics are included. */
  public double getDirreqV3Share();

  /* Return statistics on directory request responses for v2 network
   * statuses with map keys being response strings and map values being
   * response numbers rounded up to the nearest multiple of 4, or null if
   * no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV2Resp();

  /* Return statistics on directory request responses for v3 network
   * status consensuses with map keys being response strings and map
   * values being response numbers rounded up to the nearest multiple of
   * 4, or null if no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV3Resp();

  /* Return statistics on direct directory requests asking for v2 network
   * statuses with map keys being statistic keys and map values being
   * statistic values, or null if no such statistics are included. */
  public SortedMap<String, Integer> getDirreqV2DirectDl();

  /* Return statistics on direct directory requests asking for v3 network
   * status consensuses with map keys being statistic keys and map
   * values being statistic values, or null if no such statistics are
   * included. */
  public SortedMap<String, Integer> getDirreqV3DirectDl();

  /* Return statistics on tunneled directory requests asking for v2
   * network statuses with map keys being statistic keys and map values
   * being statistic values, or null if no such statistics are
   * included. */
  public SortedMap<String, Integer> getDirreqV2TunneledDl();

  /* Return statistics on tunneled directory requests asking for v3
   * network status consensuses with map keys being statistic keys and map
   * values being statistic values, or null if no such statistics are
   * included. */
  public SortedMap<String, Integer> getDirreqV3TunneledDl();

  /* Return the directory request read history contained in this
   * descriptor, or null if no directory request read history is
   * contained. */
  public BandwidthHistory getDirreqReadHistory();

  /* Return the directory request write history contained in this
   * descriptor, or null if no directory request write history is
   * contained. */
  public BandwidthHistory getDirreqWriteHistory();

  /* Return the end of the included entry statistics interval, or -1 if no
   * entry statistics are included. */
  public long getEntryStatsEndMillis();

  /* Return the interval length of the included entry statistics, or -1 if
   * no entry statistics are included. */
  public long getEntryStatsIntervalLength();

  /* Return statistics on client IP addresses with map keys being country
   * codes and map values being the number of unique IP addresses that
   * have connected from that country rounded up to the nearest multiple
   * of 8, or null if no entry statistics are included. */
  public SortedMap<String, Integer> getEntryIps();

  /* Return the end of the included cell statistics interval, or -1 if no
   * cell statistics are included. */
  public long getCellStatsEndMillis();

  /* Return the interval length of the included cell statistics, or -1 if
   * no cell statistics are included. */
  public long getCellStatsIntervalLength();

  /* Return the mean number of processed cells per circuit by circuit
   * deciles. */
  public List<Integer> getCellProcessedCells();

  /* Return the mean number of cells contained in circuit queues by
   * circuit deciles. */
  public List<Integer> getCellQueueCells();

  /* Return the mean times in milliseconds that cells spend in circuit
   * queues by circuit deciles. */
  public List<Integer> getCellTimeInQueue();

  /* Return the mean number of circuits included in any of the cell
   * statistics deciles, or -1 if no cell statistics are included. */
  public int getCellCircuitsPerDecile();

  /* Return the end of the included statistics interval on bi-directional
   * connection usage, or -1 if no such statistics are included. */
  public long getConnBiDirectStatsEndMillis();

  /* Return the interval length of the included statistics on
   * bi-directional connection usage, or -1 if no such statistics are
   * included. */
  public long getConnBiDirectIntervalLength();

  /* Return the number of connections on which this relay read and wrote
   * less than 2 KiB/s in a 10-second interval, or -1 if no statistics on
   * bi-directional connection usage are included. */
  public int getConnBiDirectBelow();

  /* Return the number of connections on which this relay read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in read direction than in write direction, or -1 if no statistics on
   * bi-directional connection usage are included. */
  public int getConnBiDirectRead();

  /* Return the number of connections on which this relay read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in write direction than in read direction, or -1 if no statistics on
   * bi-directional connection usage are included. */
  public int getConnBiDirectWrite();

  /* Return the number of connections on which this relay read and wrote
   * at least 2 KiB/s in a 10-second interval but not 10 times more in
   * either direction, or -1 if no statistics on bi-directional connection
   * usage are included. */
  public int getConnBiDirectBoth();

  /* Return the end of the included exit statistics interval, or -1 if no
   * exit statistics are included. */
  public long getExitStatsEndMillis();

  /* Return the interval length of the included exit statistics, or -1 if
   * no exit statistics are included. */
  public long getExitStatsIntervalLength();

  /* Return statistics on KiB written by port with map keys being ports
   * and map values being KiB rounded up to the next full KiB, or null if
   * no exit statistics are included. */
  public SortedMap<Integer, Integer> getExitKibibytesWritten();

  /* Return statistics on KiB read by port with map keys being ports and
   * map values being KiB rounded up to the next full KiB, or null if no
   * exit statistics are included. */
  public SortedMap<Integer, Integer> getExitKibibytesRead();

  /* Return statistics on opened exit streams with map keys being ports
   * and map values being the number of opened streams, rounded up to the
   * nearest multiple of 4, or null if no exit statistics are included. */
  public SortedMap<Integer, Integer> getExitStreamsOpened();
}

