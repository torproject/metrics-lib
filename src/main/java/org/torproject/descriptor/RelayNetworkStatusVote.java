/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

/**
 * Contains a network status vote in the version 3 directory protocol.
 *
 * <p>Directory authorities in the version 3 of the directory protocol
 * periodically generate a view of the current descriptors and status for
 * known relays and send a signed summary of this view to the other
 * authorities, which is this document.  The authorities compute the
 * result of this vote and sign a network status consensus containing the
 * result of the vote ({@link RelayNetworkStatusConsensus}).</p>
 *
 * @since 1.0.0
 */
public interface RelayNetworkStatusVote extends Descriptor {

  /**
   * Return the document format version of this descriptor which is 3 or
   * higher.
   *
   * @since 1.0.0
   */
  public int getNetworkStatusVersion();

  /**
   * Return the list of consensus method numbers supported by this
   * authority, or null if the descriptor doesn't say so, which would mean
   * that only method 1 is supported.
   *
   * @since 1.0.0
   */
  public List<Integer> getConsensusMethods();

  /**
   * Return the time in milliseconds since the epoch when this descriptor
   * was published.
   *
   * @since 1.0.0
   */
  public long getPublishedMillis();

  /**
   * Return the time in milliseconds since the epoch at which the
   * consensus is supposed to become valid.
   *
   * @since 1.0.0
   */
  public long getValidAfterMillis();

  /**
   * Return the time in milliseconds since the epoch until which the
   * consensus is supposed to be the freshest that is available.
   *
   * @since 1.0.0
   */
  public long getFreshUntilMillis();

  /**
   * Return the time in milliseconds since the epoch until which the
   * consensus is supposed to be valid.
   *
   * @since 1.0.0
   */
  public long getValidUntilMillis();

  /**
   * Return the number of seconds that the directory authorities will
   * allow to collect votes from the other authorities when producing the
   * next consensus.
   *
   * @since 1.0.0
   */
  public long getVoteSeconds();

  /**
   * Return the number of seconds that the directory authorities will
   * allow to collect signatures from the other authorities when producing
   * the next consensus.
   *
   * @since 1.0.0
   */
  public long getDistSeconds();

  /**
   * Return recommended Tor versions for server usage, or null if the
   * authority does not recommend server versions.
   *
   * @since 1.0.0
   */
  public List<String> getRecommendedServerVersions();

  /**
   * Return recommended Tor versions for client usage, or null if the
   * authority does not recommend client versions.
   *
   * @since 1.0.0
   */
  public List<String> getRecommendedClientVersions();

  /**
   * Return the version numbers of all protocols that clients should support,
   * or null if the vote does not contain an opinion about protocol versions.
   *
   * @since 1.6.0
   */
  public SortedMap<String, SortedSet<Long>> getRecommendedClientProtocols();

  /**
   * Return the version numbers of all protocols that relays should support,
   * or null if the vote does not contain an opinion about protocol versions.
   *
   * @since 1.6.0
   */
  public SortedMap<String, SortedSet<Long>> getRecommendedRelayProtocols();

  /**
   * Return the version numbers of all protocols that clients must support,
   * or null if the vote does not contain an opinion about protocol versions.
   *
   * @since 1.6.0
   */
  public SortedMap<String, SortedSet<Long>> getRequiredClientProtocols();

  /**
   * Return the version numbers of all protocols that relays must support,
   * or null if the vote does not contain an opinion about protocol versions.
   *
   * @since 1.6.0
   */
  public SortedMap<String, SortedSet<Long>> getRequiredRelayProtocols();

  /**
   * Return a list of software packages and their versions together with a
   * URL and one or more digests in the format <code>PackageName Version
   * URL DIGESTS</code> that are known by this directory authority, or
   * null if this descriptor does not contain package information.
   *
   * @since 1.3.0
   */
  public List<String> getPackageLines();

  /**
   * Return known relay flags by this authority.
   *
   * @since 1.0.0
   */
  public SortedSet<String> getKnownFlags();

  /**
   * Return the minimum uptime in seconds that this authority requires
   * for assigning the Stable flag, or -1 if the authority doesn't report
   * this value.
   *
   * @since 1.0.0
   */
  public long getStableUptime();

  /**
   * Return the minimum MTBF (mean time between failure) that this
   * authority requires for assigning the Stable flag, or -1 if the
   * authority doesn't report this value.
   *
   * @since 1.0.0
   */
  public long getStableMtbf();

  /**
   * Return the minimum bandwidth that this authority requires for
   * assigning the Fast flag, or -1 if the authority doesn't report this
   * value.
   *
   * @since 1.0.0
   */
  public long getFastBandwidth();

  /**
   * Return the minimum WFU (weighted fractional uptime) in percent that
   * this authority requires for assigning the Guard flag, or -1 if the
   * authority doesn't report this value.
   *
   * @since 1.0.0
   */
  public double getGuardWfu();

  /**
   * Return the minimum weighted time in seconds that this authority
   * needs to know about a relay before assigning the Guard flag, or -1 if
   * the authority doesn't report this information.
   *
   * @since 1.0.0
   */
  public long getGuardTk();

  /**
   * Return the minimum bandwidth that this authority requires for
   * assigning the Guard flag if exits can be guards, or -1 if the
   * authority doesn't report this value.
   *
   * @since 1.0.0
   */
  public long getGuardBandwidthIncludingExits();

  /**
   * Return the minimum bandwidth that this authority requires for
   * assigning the Guard flag if exits can not be guards, or -1 if the
   * authority doesn't report this value.
   *
   * @since 1.0.0
   */
  public long getGuardBandwidthExcludingExits();

  /**
   * Return 1 if the authority has measured enough MTBF info to use the
   * MTBF requirement instead of the uptime requirement for assigning the
   * Stable flag, 0 if not, or -1 if the authority doesn't report this
   * information.
   *
   * @since 1.0.0
   */
  public int getEnoughMtbfInfo();

  /**
   * Return 1 if the authority has enough measured bandwidths that it'll
   * ignore the advertised bandwidth claims of routers without measured
   * bandwidth, 0 if not, or -1 if the authority doesn't report this
   * information.
   *
   * @since 1.1.0
   */
  public int getIgnoringAdvertisedBws();

  /**
   * Return consensus parameters contained in this descriptor with map
   * keys being case-sensitive parameter identifiers and map values being
   * parameter values, or null if the authority doesn't include consensus
   * parameters in its vote.
   *
   * @since 1.0.0
   */
  public SortedMap<String, Integer> getConsensusParams();

  /**
   * Return the authority's nickname consisting of 1 to 19 alphanumeric
   * characters.
   *
   * @since 1.0.0
   */
  public String getNickname();

  /**
   * Return a SHA-1 digest of the authority's long-term authority
   * identity key used for the version 3 directory protocol, encoded as
   * 40 upper-case hexadecimal characters.
   *
   * @since 1.0.0
   */
  public String getIdentity();

  /**
   * Return the authority's hostname.
   *
   * @since 1.2.0
   */
  public String getHostname();

  /**
   * Return the authority's primary IPv4 address in dotted-quad format,
   * or null if the descriptor does not contain an address.
   *
   * @since 1.0.0
   */
  public String getAddress();

  /**
   * Return the TCP port where this authority accepts directory-related
   * HTTP connections, or 0 if the authority does not accept such
   * connections.
   *
   * @since 1.0.0
   */
  public int getDirport();

  /**
   * Return the TCP port where this authority accepts TLS connections for
   * the main OR protocol, or 0 if the authority does not accept such
   * connections.
   *
   * @since 1.0.0
   */
  public int getOrport();

  /**
   * Return the contact information for this authority, which may contain
   * non-ASCII characters, or null if no contact information is included
   * in the descriptor.
   *
   * @since 1.0.0
   */
  public String getContactLine();

  /**
   * Return the version of the directory key certificate used by this
   * authority, which must be 3 or higher.
   *
   * @since 1.0.0
   */
  public int getDirKeyCertificateVersion();

  /**
   * Return the SHA-1 digest for an obsolete authority identity key still
   * used by this authority to keep older clients working, or null if this
   * authority does not use such a key.
   *
   * @since 1.0.0
   */
  public String getLegacyDirKey();

  /**
   * Return the authority's identity key in PEM format.
   *
   * @since 1.2.0
   */
  public String getDirIdentityKey();

  /**
   * Return the time in milliseconds since the epoch when the authority's
   * signing key and corresponding key certificate were generated.
   *
   * @since 1.0.0
   */
  public long getDirKeyPublishedMillis();

  /**
   * Return the time in milliseconds since the epoch after which the
   * authority's signing key is no longer valid.
   *
   * @since 1.0.0
   */
  public long getDirKeyExpiresMillis();

  /**
   * Return the authority's signing key in PEM format.
   *
   * @since 1.2.0
   */
  public String getDirSigningKey();

  /**
   * Return the SHA-1 digest of the authority's signing key, encoded as
   * 40 upper-case hexadecimal characters, or null if this digest cannot
   * be obtained from the directory signature.
   *
   * @deprecated Removed in order to be more explicit that authorities may
   *     use different digest algorithms than "sha1"; see
   *     {@link #getSignatures()} and
   *     {@link DirectorySignature#getSigningKeyDigest()} for
   *     alternatives.
   *
   * @since 1.0.0
   */
  public String getSigningKeyDigest();

  /**
   * Return the signature of the authority's identity key made using the
   * authority's signing key, or null if the vote does not contain such a
   * signature.
   *
   * @since 1.2.0
   */
  public String getDirKeyCrosscert();

  /**
   * Return the certificate signature from the initial item
   * "dir-key-certificate-version" until the final item
   * "dir-key-certification", signed with the authority identity key.
   *
   * @since 1.2.0
   */
  public String getDirKeyCertification();

  /**
   * Return status entries for each contained server, with map keys being
   * SHA-1 digests of the servers' public identity keys, encoded as 40
   * upper-case hexadecimal characters.
   *
   * @since 1.0.0
   */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();

  /**
   * Return whether a status entry with the given relay fingerprint
   * (SHA-1 digest of the server's public identity key, encoded as 40
   * upper-case hexadecimal characters) exists; convenience method for
   * {@code getStatusEntries().containsKey(fingerprint)}.
   *
   * @since 1.0.0
   */
  public boolean containsStatusEntry(String fingerprint);

  /**
   * Return a status entry by relay fingerprint (SHA-1 digest of the
   * server's public identity key, encoded as 40 upper-case hexadecimal
   * characters), or null if no such status entry exists; convenience
   * method for {@code getStatusEntries().get(fingerprint)}.
   *
   * @since 1.0.0
   */
  public NetworkStatusEntry getStatusEntry(String fingerprint);

  /**
   * Return the directory signature of this vote, with the single map key
   * being the SHA-1 digest of the authority's identity key in the version
   * 3 directory protocol, encoded as 40 upper-case hexadecimal
   * characters.
   *
   * @deprecated Replaced by {@link #getSignatures()} which permits an
   *     arbitrary number of signatures made by the authority using the
   *     same identity key digest and different algorithms.
   *
   * @since 1.0.0
   */
  public SortedMap<String, DirectorySignature> getDirectorySignatures();

  /**
   * Return a list of signatures contained in this vote, which is
   * typically a single signature made by the authority but which may also
   * be more than one signature made with different keys or algorithms.
   *
   * @since 1.3.0
   */
  public List<DirectorySignature> getSignatures();
}

