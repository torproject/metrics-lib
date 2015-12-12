/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.Map;
import java.util.Set;

/* Exit list containing all known exit scan results at a given time. */
public interface ExitList extends Descriptor {

  public final static String EOL = "\n";

  /* Exit list entry containing results from a single exit scan. */
  public interface Entry {

    /* Return the scanned relay's fingerprint. */
    public String getFingerprint();

    /* Return the publication time of the scanned relay's last known
     * descriptor. */
    public long getPublishedMillis();

    /* Return the publication time of the network status that this scan
     * was based on. */
    public long getLastStatusMillis();

    /* Return the IP addresses that were determined in the scan. */
    public Map<String, Long> getExitAddresses();
  }

  /* Return the download time of the exit list. */
  public long getDownloadedMillis();

  /* Return the unordered set of exit scan results. */
  /* Use getEntries instead. */
  @Deprecated
  public Set<ExitListEntry> getExitListEntries();

  /* Return the unordered set of exit scan results. */
  public Set<ExitList.Entry> getEntries();
}

