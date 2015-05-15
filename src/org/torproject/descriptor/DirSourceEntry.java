/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

public interface DirSourceEntry {

  /* Return the raw dir-source bytes. */
  public byte[] getDirSourceEntryBytes();

  /* Return the directory nickname. */
  public String getNickname();

  /* Return the identity fingerprint. */
  public String getIdentity();

  /* Return the IP address. */
  public String getIp();

  /* Return the DirPort. */
  public int getDirPort();

  /* Return the ORPort. */
  public int getOrPort();

  /* Return whether the dir-source was created using a legacy key. */
  public boolean isLegacy();

  /* Return the contact line. */
  public String getContactLine();

  /* Return the vote digest. */
  public String getVoteDigest();
}

