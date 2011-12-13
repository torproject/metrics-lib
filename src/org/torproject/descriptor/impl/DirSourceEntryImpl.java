/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import org.torproject.descriptor.DirSourceEntry;

public class DirSourceEntryImpl implements DirSourceEntry {

  private byte[] dirSourceEntryBytes;
  public byte[] getDirSourceEntryBytes() {
    return this.dirSourceEntryBytes;
  }

  protected DirSourceEntryImpl(byte[] dirSourceEntryBytes)
      throws ParseException {
    this.dirSourceEntryBytes = dirSourceEntryBytes;
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.dirSourceEntryBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("dir-source ")) {
          String[] parts = line.split(" ");
          this.nickname = parts[1];
          this.identity = parts[2];
          this.ip = parts[4];
          this.dirPort = Integer.parseInt(parts[5]);
          this.orPort = Integer.parseInt(parts[6]);
        } else if (line.startsWith("contact ")) {
          this.contactLine = line.substring("contact ".length());
        } else if (line.startsWith("vote-digest ")) {
          this.voteDigest = line.split(" ")[1];
        }
      }
    } catch (IOException e) {
      /* TODO This cannot happen, right? */
    }
    /* TODO Implement some plausibility tests. */
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String identity;
  public String getIdentity() {
    return this.identity;
  }

  private String ip;
  public String getIp() {
    return this.ip;
  }

  private int dirPort;
  public int getDirPort() {
    return this.dirPort;
  }

  private int orPort;
  public int getOrPort() {
    return this.orPort;
  }

  private String contactLine;
  public String getContactLine() {
    return this.contactLine;
  }

  private String voteDigest;
  public String getVoteDigest() {
    return this.voteDigest;
  }
}

