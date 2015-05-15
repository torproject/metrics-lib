/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.RouterStatusEntry;

public class RouterStatusEntryImpl implements RouterStatusEntry {

  protected RouterStatusEntryImpl(String fingerprint, String nickname,
      boolean isLive, boolean isVerified) {
    this.fingerprint = fingerprint;
    this.nickname = nickname;
    this.isLive = isLive;
    this.isVerified = isVerified;
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private boolean isLive;
  public boolean isLive() {
    return this.isLive;
  }

  private boolean isVerified;
  public boolean isVerified() {
    return this.isVerified;
  }
}

