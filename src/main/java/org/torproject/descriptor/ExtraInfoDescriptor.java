/* Copyright 2012--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;
import java.util.Map;
import java.util.SortedMap;

/**
 * Contains a relay or sanitized bridge extra-info descriptor.
 *
 * <p>Relays publish extra-info descriptors as an addendum to server
 * descriptors ({@link ServerDescriptor}) to report extraneous information
 * to the directory authorities that clients do not need to download in
 * order to function.  This information primarily consists of statistics
 * gathered by the relay about its usage and can take up a lot of
 * descriptor space.  The separation of server descriptors and extra-info
 * descriptors has become less relevant with the introduction of
 * microdescriptors ({@link Microdescriptor}) that are derived from server
 * descriptors by the directory authority and which clients download
 * instead of server descriptors, but it persists.</p>
 *
 * <p>Bridges publish extra-info descriptors to the bridge authority for
 * the same reason, to include statistics about their usage without
 * increasing the directory protocol overhead for bridge clients.  In this
 * case, the separation of server descriptors and extra-info descriptors
 * is slightly more relevant, because there are no microdescriptors for
 * bridges, so that bridge clients still download server descriptors of
 * bridges they're using.  Another reason is that bridges need to include
 * information like details of all the transports they support in their
 * descriptors, and bridge clients using one such transport are not
 * supposed to learn the details of the other transports.</p>
 *
 * <p>It's worth noting that all contents of extra-info descriptors are
 * written and signed by relays and bridges without a third party
 * verifying their correctness.  The (bridge) directory authorities may
 * decide to exclude dishonest servers from the network statuses they
 * produce, but that wouldn't be reflected in extra-info descriptors.</p>
 * 
 * @since 1.0.0
 */
public interface ExtraInfoDescriptor extends Descriptor {

  /**
   * Return the SHA-1 descriptor digest, encoded as 40 lower-case (relay
   * descriptors) or upper-case (bridge descriptors) hexadecimal
   * characters, that is used to reference this descriptor from a server
   * descriptor.
   *
   * @since 1.7.0
   */
  String getDigestSha1Hex();

  /**
   * Return the SHA-256 descriptor digest, encoded as 43 base64
   * characters without padding characters, that may be used to reference
   * this descriptor from a server descriptor.
   *
   * @since 1.7.0
   */
  String getDigestSha256Base64();

  /**
   * Return the server's nickname consisting of 1 to 19 alphanumeric
   * characters.
   *
   * @since 1.0.0
   */
  String getNickname();

  /**
   * Return a SHA-1 digest of the server's public identity key, encoded
   * as 40 upper-case hexadecimal characters, that is typically used to
   * uniquely identify the server.
   *
   * @since 1.0.0
   */
  String getFingerprint();

  /**
   * Return the time in milliseconds since the epoch when this descriptor
   * and the corresponding server descriptor were generated.
   *
   * @since 1.0.0
   */
  long getPublishedMillis();

  /**
   * Return the server's history of read bytes, or null if the descriptor
   * does not contain a bandwidth history; older Tor versions included
   * bandwidth histories in their server descriptors
   * ({@link ServerDescriptor#getReadHistory()}).
   *
   * @since 1.0.0
   */
  BandwidthHistory getReadHistory();

  /**
   * Return the server's history of written bytes, or null if the
   * descriptor does not contain a bandwidth history; older Tor versions
   * included bandwidth histories in their server descriptors
   * ({@link ServerDescriptor#getWriteHistory()}).
   *
   * @since 1.0.0
   */
  BandwidthHistory getWriteHistory();

  /**
   * Return the server's history of written IPv6 bytes, or {@code null} if the
   * descriptor does not contain a bandwidth history.
   *
   * @since 2.14.0
   */
  BandwidthHistory getIpv6WriteHistory();

  /**
   * Return the server's history of read IPv6 bytes, or {@code null} if the
   * descriptor does not contain a bandwidth history.
   *
   * @since 2.14.0
   */
  BandwidthHistory getIpv6ReadHistory();

  /**
   * Return a SHA-1 digest of the GeoIP database file used by this server
   * to resolve client IP addresses to country codes, encoded as 40
   * upper-case hexadecimal characters, or null if no GeoIP database
   * digest is included.
   *
   * @since 1.7.0
   */
  String getGeoipDbDigestSha1Hex();

  /**
   * Return a SHA-1 digest of the GeoIPv6 database file used by this
   * server to resolve client IP addresses to country codes, encoded as 40
   * upper-case hexadecimal characters, or null if no GeoIPv6 database
   * digest is included.
   *
   * @since 1.7.0
   */
  String getGeoip6DbDigestSha1Hex();

  /**
   * Return the time in milliseconds since the epoch when the included
   * directory request statistics interval ended, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  long getDirreqStatsEndMillis();

  /**
   * Return the interval length of the included directory request
   * statistics in seconds, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  long getDirreqStatsIntervalLength();

  /**
   * Return statistics on unique IP addresses requesting v2 network
   * statuses with map keys being country codes and map values being
   * numbers of unique IP addresses rounded up to the nearest multiple of
   * 8, or null if no such statistics are included (which is the case with
   * recent Tor versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV2Ips();

  /**
   * Return statistics on unique IP addresses requesting v3 network
   * status consensuses of any flavor with map keys being country codes
   * and map values being numbers of unique IP addresses rounded up to the
   * nearest multiple of 8, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV3Ips();

  /**
   * Return statistics on directory requests for v2 network statuses with
   * map keys being country codes and map values being request numbers
   * rounded up to the nearest multiple of 8, or null if no such
   * statistics are included (which is the case with recent Tor
   * versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV2Reqs();

  /**
   * Return statistics on directory requests for v3 network status
   * consensuses of any flavor with map keys being country codes and map
   * values being request numbers rounded up to the nearest multiple of 8,
   * or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV3Reqs();

  /**
   * Return the share of requests for v2 network statuses that the server
   * expects to receive from clients, or -1.0 if this share is not
   * included (which is the case with recent Tor versions).
   *
   * @since 1.0.0
   */
  double getDirreqV2Share();

  /**
   * Return the share of requests for v3 network status consensuses of
   * any flavor that the server expects to receive from clients, or -1.0
   * if this share is not included (which is the case with recent Tor
   * versions).
   *
   * @since 1.0.0
   */
  double getDirreqV3Share();

  /**
   * Return statistics on responses to directory requests for v2 network
   * statuses with map keys being response strings and map values being
   * response numbers rounded up to the nearest multiple of 4, or null if
   * no such statistics are included (which is the case with recent Tor
   * versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV2Resp();

  /**
   * Return statistics on responses to directory requests for v3 network
   * status consensuses of any flavor with map keys being response strings
   * and map values being response numbers rounded up to the nearest
   * multiple of 4, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV3Resp();

  /**
   * Return statistics on directory requests for v2 network statuses to
   * the server's directory port with map keys being statistic keys and
   * map values being statistic values like counts or quantiles, or null
   * if no such statistics are included (which is the case with recent Tor
   * versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV2DirectDl();

  /**
   * Return statistics on directory requests for v3 network status
   * consensuses of any flavor to the server's directory port with map
   * keys being statistic keys and map values being statistic values like
   * counts or quantiles, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV3DirectDl();

  /**
   * Return statistics on directory requests for v2 network statuses
   * tunneled through a circuit with map keys being statistic keys and map
   * values being statistic values, or null if no such statistics are
   * included (which is the case with recent Tor versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV2TunneledDl();

  /**
   * Return statistics on directory requests for v3 network status
   * consensuses of any flavor tunneled through a circuit with map keys
   * being statistic keys and map values being statistic values, or null
   * if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getDirreqV3TunneledDl();

  /**
   * Return the directory request read history contained in this
   * descriptor, or null if no such history is contained.
   *
   * @since 1.0.0
   */
  BandwidthHistory getDirreqReadHistory();

  /**
   * Return the directory request write history contained in this
   * descriptor, or null if no such history is contained.
   *
   * @since 1.0.0
   */
  BandwidthHistory getDirreqWriteHistory();

  /**
   * Return the time in milliseconds since the epoch when the included
   * entry statistics interval ended, or -1 if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  long getEntryStatsEndMillis();

  /**
   * Return the interval length of the included entry statistics in
   * seconds, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  long getEntryStatsIntervalLength();

  /**
   * Return statistics on client IP addresses with map keys being country
   * codes and map values being the number of unique IP addresses that
   * have connected from that country rounded up to the nearest multiple
   * of 8, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getEntryIps();

  /**
   * Return the time in milliseconds since the epoch when the included
   * cell statistics interval ended, or -1 if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  long getCellStatsEndMillis();

  /**
   * Return the interval length of the included cell statistics in
   * seconds, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  long getCellStatsIntervalLength();

  /**
   * Return the mean number of processed cells per circuit by circuit
   * decile starting with the loudest decile at index 0 and the quietest
   * decile at index 8, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  List<Integer> getCellProcessedCells();

  /**
   * Return the mean number of cells contained in circuit queues by
   * circuit decile starting with the loudest decile at index 0 and the
   * quietest decile at index 8, or null if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  List<Double> getCellQueuedCells();

  /**
   * Return the mean times in milliseconds that cells spend in circuit
   * queues by circuit decile starting with the loudest decile at index 0
   * and the quietest decile at index 8, or null if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  List<Integer> getCellTimeInQueue();

  /**
   * Return the mean number of circuits included in any of the cell
   * statistics deciles, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  int getCellCircuitsPerDecile();

  /**
   * Return the time in milliseconds since the epoch when the included
   * statistics on bi-directional connection usage ended, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  long getConnBiDirectStatsEndMillis();

  /**
   * Return the interval length of the included statistics on
   * bi-directional connection usage in seconds, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  long getConnBiDirectStatsIntervalLength();

  /**
   * Return the number of connections on which this server read and wrote
   * less than 2 KiB/s in a 10-second interval, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  int getConnBiDirectBelow();

  /**
   * Return the number of connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in read direction than in write direction, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  int getConnBiDirectRead();

  /**
   * Return the number of connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in write direction than in read direction, or -1 if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  int getConnBiDirectWrite();

  /**
   * Return the number of connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval but not 10 times more in
   * either direction, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  int getConnBiDirectBoth();

  /**
   * Return the time in milliseconds since the epoch when the included
   * statistics on bi-directional IPv6 connection usage ended, or -1 if no such
   * statistics are included.
   *
   * @since 2.14.0
   */
  long getIpv6ConnBiDirectStatsEndMillis();

  /**
   * Return the interval length of the included statistics on
   * bi-directional IPv6 connection usage in seconds, or -1 if no such
   * statistics are included.
   *
   * @since 2.14.0
   */
  long getIpv6ConnBiDirectStatsIntervalLength();

  /**
   * Return the number of IPv6 connections on which this server read and wrote
   * less than 2 KiB/s in a 10-second interval, or -1 if no such
   * statistics are included.
   *
   * @since 2.14.0
   */
  int getIpv6ConnBiDirectBelow();

  /**
   * Return the number of IPv6 connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in read direction than in write direction, or -1 if no such
   * statistics are included.
   *
   * @since 2.14.0
   */
  int getIpv6ConnBiDirectRead();

  /**
   * Return the number of IPv6 connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval and at least 10 times more
   * in write direction than in read direction, or -1 if no such
   * statistics are included.
   *
   * @since 2.14.0
   */
  int getIpv6ConnBiDirectWrite();

  /**
   * Return the number of IPv6 connections on which this server read and wrote
   * at least 2 KiB/s in a 10-second interval but not 10 times more in
   * either direction, or -1 if no such statistics are included.
   *
   * @since 2.14.0
   */
  int getIpv6ConnBiDirectBoth();

  /**
   * Return the time in milliseconds since the epoch when the included
   * exit statistics interval ended, or -1 if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  long getExitStatsEndMillis();

  /**
   * Return the interval length of the included exit statistics in
   * seconds, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  long getExitStatsIntervalLength();

  /**
   * Return statistics on KiB written to streams exiting the Tor network
   * by target TCP port with map keys being string representations of
   * ports (or {@code "other"}) and map values being KiB rounded up to the
   * next full KiB, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Long> getExitKibibytesWritten();

  /**
   * Return statistics on KiB read from streams exiting the Tor network
   * by target TCP port with map keys being string representations of
   * ports (or {@code "other"}) and map values being KiB rounded up to the
   * next full KiB, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Long> getExitKibibytesRead();

  /**
   * Return statistics on opened streams exiting the Tor network by
   * target TCP port with map keys being string representations of ports
   * (or {@code "other"}) and map values being the number of opened
   * streams, rounded up to the nearest multiple of 4, or null if no such
   * statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Long> getExitStreamsOpened();

  /**
   * Return the time in milliseconds since the epoch when the included
   * "geoip" statistics interval started, or -1 if no such statistics are
   * included (which is the case except for very old Tor versions).
   *
   * @since 1.0.0
   */
  long getGeoipStartTimeMillis();

  /**
   * Return statistics on the origin of client IP addresses with map keys
   * being country codes and map values being the number of unique IP
   * addresses that have connected from that country between the start of
   * the statistics interval and the descriptor publication time rounded
   * up to the nearest multiple of 8, or null if no such statistics are
   * included (which is the case except for very old Tor versions).
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getGeoipClientOrigins();

  /**
   * Return the time in milliseconds since the epoch when the included
   * bridge statistics interval ended, or -1 if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  long getBridgeStatsEndMillis();

  /**
   * Return the interval length of the included bridge statistics in
   * seconds, or -1 if no such statistics are included.
   *
   * @since 1.0.0
   */
  long getBridgeStatsIntervalLength();

  /**
   * Return statistics on bridge client IP addresses by country with map
   * keys being country codes and map values being the number of unique IP
   * addresses that have connected from that country rounded up to the
   * nearest multiple of 8, or null if no such statistics are included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getBridgeIps();

  /**
   * Return statistics on bridge client IP addresses by IP version with
   * map keys being protocol families, e.g., {@code "v4"} or {@code "v6"},
   * and map values being the number of unique IP addresses rounded up to
   * the nearest multiple of 8, or null if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getBridgeIpVersions();

  /**
   * Return statistics on bridge client IP addresses by transport with
   * map keys being pluggable transport names, e.g., {@code "obfs2"} or
   * {@code "obfs3"} for known transports, {@code "<OR>"} for the default
   * onion routing protocol, or {@code "<??>"} for an unknown transport,
   * and map values being the number of unique IP addresses rounded up to
   * the nearest multiple of 8, or null if no such statistics are
   * included.
   *
   * @since 1.0.0
   */
  SortedMap<String, Integer> getBridgeIpTransports();

  /**
   * Return the (possibly empty) list of pluggable transports supported
   * by this server.
   *
   * @since 1.0.0
   */
  List<String> getTransports();

  /**
   * Return the time in milliseconds since the epoch when the included
   * hidden-service statistics interval ended, or -1 if no such statistics
   * are included.
   *
   * @since 1.1.0
   */
  long getHidservStatsEndMillis();

  /**
   * Return the interval length of the included hidden-service statistics
   * in seconds, or -1 if no such statistics are included.
   *
   * @since 1.1.0
   */
  long getHidservStatsIntervalLength();

  /**
   * Return the approximate number of RELAY cells seen in either
   * direction on a circuit after receiving and successfully processing a
   * RENDEZVOUS1 cell, or null if no such statistics are included.
   *
   * @since 1.1.0
   */
  Double getHidservRendRelayedCells();

  /**
   * Return the obfuscation parameters applied to the original
   * measurement value of RELAY cells seen in either direction on a
   * circuit after receiving and successfully processing a RENDEZVOUS1
   * cell, or null if no such statistics are included.
   *
   * @since 1.1.0
   */
  Map<String, Double> getHidservRendRelayedCellsParameters();

  /**
   * Return the approximate number of unique hidden-service identities
   * seen in descriptors published to and accepted by this hidden-service
   * directory, or null if no such statistics are included.
   *
   * @since 1.1.0
   */
  Double getHidservDirOnionsSeen();

  /**
   * Return the obfuscation parameters applied to the original
   * measurement value of unique hidden-service identities seen in
   * descriptors published to and accepted by this hidden-service
   * directory, or null if no such statistics are included.
   *
   * @since 1.1.0
   */
  Map<String, Double> getHidservDirOnionsSeenParameters();

  /**
   * Return the time in milliseconds since the epoch when the included
   * padding-counts statistics ended, or -1 if no such statistics are included.
   *
   * @since 1.7.0
   */
  long getPaddingCountsStatsEndMillis();

  /**
   * Return the interval length of the included padding-counts statistics in
   * seconds, or -1 if no such statistics are included.
   *
   * @since 1.7.0
   */
  long getPaddingCountsStatsIntervalLength();

  /**
   * Return padding-counts statistics, or {@code null} if no such
   * statistics are included.
   *
   * @since 1.7.0
   */
  Map<String, Long> getPaddingCounts();

  /**
   * Return the RSA-1024 signature of the PKCS1-padded descriptor digest,
   * taken from the beginning of the router line through the newline after
   * the router-signature line, or null if the descriptor doesn't contain
   * a signature (which is the case in sanitized bridge descriptors).
   *
   * @since 1.1.0
   */
  String getRouterSignature();

  /**
   * Return the Ed25519 certificate in PEM format, or null if the
   * descriptor doesn't contain one.
   *
   * @since 1.1.0
   */
  String getIdentityEd25519();

  /**
   * Return the Ed25519 master key, encoded as 43 base64 characters
   * without padding characters, which was either parsed from the optional
   * {@code "master-key-ed25519"} line or derived from the (likewise
   * optional) Ed25519 certificate following the
   * {@code "identity-ed25519"} line, or null if the descriptor contains
   * neither Ed25519 master key nor Ed25519 certificate.
   *
   * @since 1.1.0
   */
  String getMasterKeyEd25519();

  /**
   * Return the Ed25519 signature of the SHA-256 digest of the entire
   * descriptor, encoded as 86 base64 characters without padding
   * characters, from the first character up to and including the first
   * space after the {@code "router-sig-ed25519"} string, prefixed with
   * the string {@code "Tor router descriptor signature v1"}.
   *
   * @since 1.1.0
   */
  String getRouterSignatureEd25519();
}

