/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

/* Contains a relay server descriptor. */
public interface RelayServerDescriptor extends Descriptor {

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
   * the operating system. */
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

  /* Return the number of seconds that this relay has been running, or -1
   * if the descriptor does not contain an uptime line. */
  public int getUptime();

  /* Return the relay's exit policy consisting of one or more accept or
   * reject lines. */
  public List<String> getExitPolicyLines();

  /* Return the contact information for this relay, or null if no contact
   * information is included in the descriptor. */
  public String getContact();

  /* Return the nicknames or ($-prefixed) fingerprints contained in the
   * family line of this relay, or null if the descriptor does not contain
   * a family line. */
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

