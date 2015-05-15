/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

/* Status entry contained in a v1 signed directory. */
public interface RouterStatusEntry {

  /* Return the relay nickname, or null if the relay is unverified. */
  public String getNickname();

  /* Return the relay fingerprint. */
  public String getFingerprint();

  /* Return whether the relay is verified. */
  public boolean isVerified();

  /* Return whether the relay is live. */
  public boolean isLive();
}

