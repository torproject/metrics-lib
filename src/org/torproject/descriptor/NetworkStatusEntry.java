/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;
import java.util.Set;
import java.util.SortedSet;

/* Status entry contained in a network status with version 2 or higher or
 * in a bridge network status. */
public interface NetworkStatusEntry {

  /* Return the raw status entry bytes. */
  public byte[] getStatusEntryBytes();

  /* Return the relay nickname. */
  public String getNickname();

  /* Return the relay fingerprint. */
  public String getFingerprint();

  /* Return the descriptor identity or null if the containing status is a
   * microdesc consensus. */
  public String getDescriptor();

  /* Return the publication timestamp. */
  public long getPublishedMillis();

  /* Return the IP address. */
  public String getAddress();

  /* Return the ORPort. */
  public int getOrPort();

  /* Return the DirPort. */
  public int getDirPort();

  /* Return the (possibly empty) set of microdescriptor digest(s) if the
   * containing status is a vote or microdesc consensus, or null
   * otherwise. */
  public Set<String> getMicrodescriptorDigests();

  /* Return the relay's additional OR addresses and ports contained in
   * or-address lines, or an empty list if the network status doesn't
   * contain such lines. */
  public List<String> getOrAddresses();

  /* Return the relay flags or null if the status entry didn't contain any
   * relay flags. */
  public SortedSet<String> getFlags();

  /* Return the Tor software version or null if the status entry didn't
   * contain a version line. */
  public String getVersion();

  /* Return the bandwidth weight or -1L if the status entry didn't
   * contain a bandwidth line. */
  public long getBandwidth();

  /* Return the measured bandwidth or -1L if the status entry didn't
   * contain a bandwidth line or didn't contain a Measured= keyword in its
   * bandwidth line. */
  public long getMeasured();

  /* Return whether the status entry contained an Unmeasured=1 entry in
   * its bandwidth line, meaning that the bandwidth authorities didn't
   * measure this relay yet.  Only included in consensuses using method
   * 17 or higher. */
  public boolean getUnmeasured();

  /* Return the default policy of the port summary or null if the status
   * entry didn't contain a port summary line. */
  public String getDefaultPolicy();

  /* Return the port list of the port summary or null if the status entry
   * didn't contain a port summary line. */
  public String getPortList();
}

