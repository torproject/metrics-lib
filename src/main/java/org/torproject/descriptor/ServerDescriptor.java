/* Copyright 2011--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

/**
 * Contains a relay or sanitized bridge server descriptor.
 *
 * <p>Relays publish server descriptors to the directory authorities to
 * register in the network.  Server descriptors contain information about
 * the capabilities of a server, like their exit policy, that clients use
 * to select servers for their circuits (along with information provided
 * by directory authorities on reachability, stability, and capacity of
 * servers).  Server descriptors also contain network addresses and
 * cryptographic material that clients use to build circuits.</p>
 *
 * <p>Prior to the introduction of microdescriptors
 * ({@link Microdescriptor}), the directory authorities included
 * cryptographic digests of server descriptors in network statuses
 * ({@link RelayNetworkStatusConsensus}) and clients downloaded all
 * referenced server descriptors.  Nowadays, the directory authorities
 * derive microdescriptors from server descriptors and reference those
 * in network statuses, and clients only download microdescriptors instead
 * of server descriptors.</p>
 *
 * <p>Bridges publish server descriptors to the bridge directory
 * authority, also to announce themselves in the network.  The bridge
 * directory authority compiles a list of available bridges
 * ({@link BridgeNetworkStatus}) for the bridge distribution service
 * BridgeDB.  There are no microdescriptors for bridges, so that bridge
 * clients still rely on downloading bridge server descriptors directly
 * from the bridge they're connecting to.</p>
 *
 * <p>It's worth noting that all contents of server descriptors are
 * written and signed by relays and bridges without a third party
 * verifying their correctness.  The (bridge) directory authorities may
 * decide to exclude dishonest servers from the network statuses they
 * produce, but that wouldn't be reflected in server descriptors.</p>
 *
 * @since 1.0.0
 */
public interface ServerDescriptor extends Descriptor {

  /**
   * Return the SHA-1 descriptor digest, encoded as 40 lower-case (relay
   * descriptors) or upper-case (bridge descriptors) hexadecimal
   * characters, that is used to reference this descriptor from a network
   * status descriptor.
   *
   * @since 1.7.0
   */
  String getDigestSha1Hex();

  /**
   * Return the SHA-256 descriptor digest, encoded as 43 base64
   * characters without padding characters, that may be used to reference
   * this server descriptor from a network status descriptor.
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
   * Return the server's primary IPv4 address in dotted-quad format.
   *
   * @since 1.0.0
   */
  String getAddress();

  /**
   * Return the TCP port where this server accepts TLS connections for
   * the main OR protocol, or 0 if the server does not accept such
   * connections.
   *
   * @since 1.0.0
   */
  int getOrPort();

  /**
   * Return the TCP port where this server accepts SOCKS connections,
   * which is deprecated in the Tor Protocol and should always be 0.
   *
   * @since 1.0.0
   */
  int getSocksPort();

  /**
   * Return the TCP port where this server accepts directory-related HTTP
   * connections, or 0 if the server does not accept such connections.
   *
   * @since 1.0.0
   */
  int getDirPort();

  /**
   * Return IP addresses and TCP ports where this server accepts TLS
   * connections for the main OR protocol, or an empty list if the server
   * does not support additional addresses or ports; entries are given in
   * the order as they are listed in the descriptor; IPv4 addresses are
   * given in dotted-quad format, IPv6 addresses use the colon-separated
   * hexadecimal format surrounded by square brackets, and TCP ports are
   * separated from the IP address using a colon.
   *
   * @since 1.0.0
   */
  List<String> getOrAddresses();

  /**
   * Return the average bandwidth in bytes per second that the server is
   * willing to sustain over long periods.
   *
   * @since 1.0.0
   */
  int getBandwidthRate();

  /**
   * Return the burst bandwidth in bytes per second that the server is
   * willing to sustain in very short intervals.
   *
   * @since 1.0.0
   */
  int getBandwidthBurst();

  /**
   * Return the observed bandwidth in bytes per second as an estimate of
   * the capacity that the server can handle, or -1 if the descriptor
   * doesn't contain an observed bandwidth value (which is the case for
   * Tor 0.0.8 or older).
   *
   * @since 1.0.0
   */
  int getBandwidthObserved();

  /**
   * Return a human-readable string describing the Tor software version
   * and the operating system of this server, which may contain non-ASCII
   * characters, typically written as {@code "Tor $version on $system"},
   * or null if this descriptor does not contain a platform line.
   *
   * @since 1.0.0
   */
  String getPlatform();

  /**
   * Return the version numbers of all protocols supported by this server, or
   * null if this descriptor does not specify supported protocol versions.
   *
   * @since 1.6.0
   */
  SortedMap<String, SortedSet<Long>> getProtocols();

  /**
   * Return the time in milliseconds since the epoch when this descriptor
   * and the corresponding extra-info descriptor were generated.
   *
   * @since 1.0.0
   */
  long getPublishedMillis();

  /**
   * Return a SHA-1 digest of the server's public identity key, encoded
   * as 40 upper-case hexadecimal characters (without spaces after every 4
   * characters as opposed to the encoding in the descriptor), that is
   * typically used to uniquely identify the server, or null if this
   * descriptor does not contain a fingerprint line.
   *
   * @since 1.0.0
   */
  String getFingerprint();

  /**
   * Return whether the server was hibernating when this descriptor was
   * published and should not be used to build circuits.
   *
   * @since 1.0.0
   */
  boolean isHibernating();

  /**
   * Return the number of seconds that the server process has been
   * running (which might even be negative in a few descriptors due to a
   * bug that was fixed in Tor 0.1.2.7-alpha), or null if the descriptor
   * does not contain an uptime line.
   *
   * @since 1.0.0
   */
  Long getUptime();

  /**
   * Return the RSA-1024 public key in PEM format used to encrypt CREATE
   * cells for this server, or null if the descriptor doesn't contain an
   * onion key (which is the case in sanitized bridge descriptors).
   *
   * @since 1.0.0
   */
  String getOnionKey();

  /**
   * Return the RSA-1024 public key in PEM format used by this server as
   * long-term identity key, or null if the descriptor doesn't contain a
   * signing key (which is the case in sanitized bridge descriptors).
   *
   * @since 1.0.0
   */
  String getSigningKey();

  /**
   * Return the server's exit policy consisting of one or more accept or
   * reject rules that the server follows when deciding whether to allow a
   * new stream to a given IP address and TCP port.
   *
   * @since 1.0.0
   */
  List<String> getExitPolicyLines();

  /**
   * Return the RSA-1024 signature of the PKCS1-padded descriptor digest,
   * taken from the beginning of the router line through the newline after
   * the router-signature line, or null if the descriptor doesn't contain
   * a signature (which is the case in sanitized bridge descriptors).
   *
   * @since 1.0.0
   */
  String getRouterSignature();

  /**
   * Return the contact information for this server, which may contain
   * non-ASCII characters, or null if no contact information is included
   * in the descriptor.
   *
   * @since 1.0.0
   */
  String getContact();

  /**
   * Return nicknames, $-prefixed identity fingerprints, or tuples of the
   * format {@code $fingerprint=nickname} or {@code $fingerprint~nickname}
   * of servers contained in this server's family, or null if the
   * descriptor does not contain a family line.
   *
   * @since 1.0.0
   */
  List<String> getFamilyEntries();

  /**
   * Return the server's history of read bytes, or null if the descriptor
   * does not contain a bandwidth history; current Tor versions include
   * bandwidth histories in their extra-info descriptors
   * ({@link ExtraInfoDescriptor#getReadHistory()}), not in their server
   * descriptors.
   *
   * @since 1.0.0
   */
  BandwidthHistory getReadHistory();

  /**
   * Return the server's history of written bytes, or null if the
   * descriptor does not contain a bandwidth history; current Tor versions
   * include bandwidth histories in their extra-info descriptors
   * ({@link ExtraInfoDescriptor#getWriteHistory()}), not in their server
   * descriptors.
   *
   * @since 1.0.0
   */
  BandwidthHistory getWriteHistory();

  /**
   * Return true if the server uses the enhanced DNS logic, or false if
   * doesn't use it or doesn't include an eventdns line in its
   * descriptor; current Tor versions should be presumed to have the evdns
   * backend.
   *
   * @since 1.0.0
   */
  boolean getUsesEnhancedDnsLogic();

  /**
   * Return whether this server is a directory cache that provides
   * extra-info descriptors.
   *
   * @since 1.0.0
   */
  boolean getCachesExtraInfo();

  /**
   * Return the SHA-1 digest of the server's extra-info descriptor,
   * encoded as 40 upper-case hexadecimal characters, or null if the
   * server did not upload a corresponding extra-info descriptor.
   *
   * @since 1.7.0
   */
  String getExtraInfoDigestSha1Hex();

  /**
   * Return the SHA-256 digest of the server's extra-info descriptor,
   * encoded as 43 base64 characters without padding characters, or null
   * if the server either did not upload a corresponding extra-info
   * descriptor or did not refer to it using a SHA-256 digest.
   *
   * @since 1.7.0
   */
  String getExtraInfoDigestSha256Base64();

  /**
   * Return the list of hidden service descriptor version numbers that
   * this server stores and serves, or null if it doesn't store and serve
   * any hidden service descriptors.
   *
   * @deprecated Replaced with {@link #isHiddenServiceDir}, because Tor has
   *     never supported versions in the hidden-service-dir descriptor line.
   *
   * @since 1.0.0
   */
  @Deprecated
  List<Integer> getHiddenServiceDirVersions();

  /**
   * Return whether this server stores and serves hidden service descriptors.
   *
   * @since 2.3.0
   */
  boolean isHiddenServiceDir();

  /**
   * Return the list of link protocol versions that this server
   * supports.
   *
   * @since 1.0.0
   */
  List<Integer> getLinkProtocolVersions();

  /**
   * Return the list of circuit protocol versions that this server
   * supports.
   *
   * @since 1.0.0
   */
  List<Integer> getCircuitProtocolVersions();

  /**
   * Return whether this server allows single-hop circuits to make exit
   * connections.
   *
   * @since 1.0.0
   */
  boolean getAllowSingleHopExits();

  /**
   * Return the default policy, {@code "accept"} or {@code "reject"}, of
   * the IPv6 port summary, or null if the descriptor didn't contain an
   * IPv6 exit-policy summary line which is equivalent to rejecting all
   * streams to IPv6 targets.
   *
   * @since 1.0.0
   */
  String getIpv6DefaultPolicy();

  /**
   * Return the port list of the IPv6 exit-policy summary, or null if the
   * descriptor didn't contain an IPv6 exit-policy summary line which is
   * equivalent to rejecting all streams to IPv6 targets.
   *
   * @since 1.0.0
   */
  String getIpv6PortList();

  /**
   * Return the curve25519 public key, encoded as 43 base64 characters
   * without padding characters, that is used for the ntor circuit
   * extended handshake, or null if the descriptor didn't contain an
   * ntor-onion-key line. */
  String getNtorOnionKey();

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

  /**
   * Return an RSA-1024 signature in PEM format, generated using the
   * server's onion key, that proves that the party creating the
   * descriptor had control over the private key corresponding to the
   * onion key, or null if the descriptor does not contain such a
   * signature.
   *
   * @since 1.1.0
   */
  String getOnionKeyCrosscert();

  /**
   * Return an Ed25519 signature in PEM format, generated using the
   * server's ntor onion key, that proves that the party creating the
   * descriptor had control over the private key corresponding to the ntor
   * onion key, or null if the descriptor does not contain such a
   * signature.
   *
   * @since 1.1.0
   */
  String getNtorOnionKeyCrosscert();

  /**
   * Return the sign of the Ed25519 public key corresponding to the ntor
   * onion key as 0 or 1, or -1 if the descriptor does not contain this
   * information.
   *
   * @since 1.1.0
   */
  int getNtorOnionKeyCrosscertSign();

  /**
   * Return whether the server accepts "tunneled" directory requests using
   * a BEGIN_DIR cell over the server's OR port.
   *
   * @since 1.3.0
   */
  boolean getTunnelledDirServer();
}

