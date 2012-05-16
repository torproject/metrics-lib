/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;

/* Contains a v2 network status. */
public interface RelayNetworkStatus extends Descriptor {

  /* Return the network status version. */
  public int getNetworkStatusVersion();

  /* Return the authority's hostname. */
  public String getHostname();

  /* Return the authority's IP address. */
  public String getAddress();

  /* Return the authority's directory port. */
  public int getDirport();

  /* Return the directory's signing key's fingerprint. */
  public String getFingerprint();

  /* Return the contact line. */
  public String getContactLine();

  /* Return the directory signing key digest. */
  public String getDirSigningKey();

  /* Return recommended server versions or null if the status doesn't
   * contain recommended server versions. */
  public List<String> getRecommendedServerVersions();

  /* Return recommended client versions or null if the status doesn't
   * contain recommended client versions. */
  public List<String> getRecommendedClientVersions();

  /* Return the published time in milliseconds. */
  public long getPublishedMillis();

  /* Return the set of flags that this directory assigns to relays, or
   * null if the status does not contain a dir-options line. */
  public SortedSet<String> getDirOptions();

  /* Return status entries, one for each contained relay. */
  public SortedMap<String, NetworkStatusEntry> getStatusEntries();

  /* Return whether a status entry with the given fingerprint exists. */
  public boolean containsStatusEntry(String fingerprint);

  /* Return a status entry by fingerprint or null if no such status entry
   * exists. */
  public NetworkStatusEntry getStatusEntry(String fingerprint);

  /* Return the directory nickname. */
  public String getNickname();

  /* Return the directory signature. */
  public String getDirectorySignature();

  /* Return the status digest that the directory authority used to sign
   * the network status. */
  public String getStatusDigest();
}

