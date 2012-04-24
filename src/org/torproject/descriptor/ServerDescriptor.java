/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

/* Contains a relay server descriptor. */
public interface ServerDescriptor extends Descriptor {

  /* Return the descriptor digest that is used to reference this server
   * descriptor in a network status. */
  public String getServerDescriptorDigest();

  /* Return the relay's nickname. */
  public String getNickname();

  /* Return the relay's IPv4 address in dotted-quad format. */
  public String getAddress();

  /* Return the relay's OR port. */
  public int getOrPort();

  /* Return the relay's SOCKS port which should always be 0. */
  public int getSocksPort();

  /* Return the relay's directory port. */
  public int getDirPort();

  /* Return the relay's additional OR addresses and ports contained in
   * or-address lines, or an empty list if the descriptor doesn't contain
   * such lines. */
  public List<String> getOrAddresses();

  /* Return the average bandwidth in bytes per second that the relay is
   * willing to sustain over long periods. */
  public int getBandwidthRate();

  /* Return the burst bandwidth in bytes per second that the relay is
   * willing to sustain in very short intervals. */
  public int getBandwidthBurst();

  /* Return the observed bandwidth in bytes per second as an estimate of
   * the capacity that the relay can handle. */
  public int getBandwidthObserved();

  /* Return the platform string containing the Tor software version and
   * the operating system, or null if this descriptor does not contain a
   * platform line. */
  public String getPlatform();

  /* Return the time when this descriptor and the corresponding extra-info
   * document was generated. */
  public long getPublishedMillis();

  /* Return the relay fingerprint, or null if this descriptor does not
   * contain a fingerprint line. */
  public String getFingerprint();

  /* Return whether the relay was hibernating when this descriptor was
   * published. */
  public boolean isHibernating();

  /* Return the number of seconds that this relay has been running (which
   * might even be negative in a few descriptors due to a bug that was
   * fixed in 0.1.2.7-alpha), or null if the descriptor does not contain
   * an uptime line. */
  public Long getUptime();

  /* Return the onion key in PEM format, or null if the descriptor
   * doesn't contain a signing key (which is the case in sanitized bridge
   * descriptors). */
  public String getOnionKey();

  /* Return the signing key in PEM format, or null if the descriptor
   * doesn't contain a signing key (which is the case in sanitized bridge
   * descriptors). */
  public String getSigningKey();

  /* Return the relay's exit policy consisting of one or more accept or
   * reject lines. */
  public List<String> getExitPolicyLines();

  /* Return the signature of the PKCS1-padded server descriptor digest, or
   * null if the descriptor doesn't contain a signature (which is the case
   * in sanitized bridge descriptors). */
  public String getRouterSignature();

  /* Return the contact information for this relay, or null if no contact
   * information is included in the descriptor. */
  public String getContact();

  /* Return the nicknames, ($-prefixed) fingerprints, or
   * $fingerprint=nickname tuples contained in the family line of this
   * relay, or null if the descriptor does not contain a family line. */
  public List<String> getFamilyEntries();

  /* Return the relay's read history.  (Current Tor versions include their
   * bandwidth histories in their extra-info descriptors, not in their
   * server descriptors.) */
  public BandwidthHistory getReadHistory();

  /* Return the relay's write history.  (Current Tor versions include
   * their bandwidth histories in their extra-info descriptors, not in
   * their server descriptors.) */
  public BandwidthHistory getWriteHistory();

  /* Return true if the relay uses the enhanced DNS logic, or false if
   * doesn't use it or doesn't include an eventdns line in its
   * descriptor. */
  public boolean getUsesEnhancedDnsLogic();

  /* Return whether this relay is a directory cache that provides
   * extra-info descriptors. */
  public boolean getCachesExtraInfo();

  /* Return the digest of the relay's extra-info descriptor, or null if
   * the relay did not upload a corresponding extra-info descriptor. */
  public String getExtraInfoDigest();

  /* Return the hidden service descriptor version(s) that this relay
   * stores and serves, or null if it doesn't store and serve any hidden
   * service descriptors. */
  public List<Integer> getHiddenServiceDirVersions();

  /* Return the list of link protocol versions that this relay
   * supports. */
  public List<Integer> getLinkProtocolVersions();

  /* Return the list of circuit protocol versions that this relay
   * supports. */
  public List<Integer> getCircuitProtocolVersions();

  /* Return whether this relay allows single-hop circuits to make exit
   * connections. */
  public boolean getAllowSingleHopExits();
}

