/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeSet;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.torproject.descriptor.NetworkStatusEntry;

public class NetworkStatusEntryImpl implements NetworkStatusEntry {

  private byte[] statusEntryBytes;
  public byte[] getStatusEntryBytes() {
    return this.statusEntryBytes;
  }

  private static SimpleDateFormat dateTimeFormat;
  static {
    dateTimeFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  protected NetworkStatusEntryImpl(byte[] statusEntryBytes)
      throws ParseException {
    this.statusEntryBytes = statusEntryBytes;
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.statusEntryBytes)));
      String line;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("r ")) {
          String[] parts = line.split(" ");
          if (parts.length < 9) {
            throw new RuntimeException("r line '" + line + "' has fewer "
                + "space-separated elements than expected.");
          }
          this.nickname = parts[1];
          this.fingerprint = Hex.encodeHexString(Base64.decodeBase64(
              parts[2] + "=")).toLowerCase();
          this.descriptor = Hex.encodeHexString(Base64.decodeBase64(
              parts[3] + "=")).toLowerCase();
          this.publishedMillis = dateTimeFormat.parse(parts[4] + " "
              + parts[5]).getTime();
          this.address = parts[6];
          this.orPort = Integer.parseInt(parts[7]);
          this.dirPort = Integer.parseInt(parts[8]);
        } else if (line.equals("s")) {
          /* No flags to add. */
        } else if (line.startsWith("s ")) {
          this.flags.addAll(Arrays.asList(line.substring("s ".length()).
              split(" ")));
        } else if (line.startsWith("v ")) {
          this.version = line.substring("v ".length());
        } else if (line.startsWith("w ")) {
          this.bandwidth = line.substring("w ".length());
        } else if (line.startsWith("p ")) {
          this.ports = line.substring(2);
        } else {
          throw new RuntimeException("Unknown line '" + line + "' in "
              + "status entry.");
        }
      }
    } catch (IOException e) {
      /* TODO Do something. */
    }
    /* TODO Add some plausibility checks, like if we have a nickname
     * etc. */
  }

  private String nickname;
  public String getNickname() {
    return this.nickname;
  }

  private String fingerprint;
  public String getFingerprint() {
    return this.fingerprint;
  }

  private String descriptor;
  public String getDescriptor() {
    return this.descriptor;
  }

  private long publishedMillis;
  public long getPublishedMillis() {
    return this.publishedMillis;
  }

  private String address;
  public String getAddress() {
    return this.address;
  }

  private int orPort;
  public int getOrPort() {
    return this.orPort;
  }

  private int dirPort;
  public int getDirPort() {
    return this.dirPort;
  }

  private SortedSet<String> flags = new TreeSet<String>();
  public SortedSet<String> getFlags() {
    return new TreeSet<String>(this.flags);
  }

  private String version;
  public String getVersion() {
    return this.version;
  }

  private String bandwidth;
  public String getBandwidth() {
    return this.bandwidth;
  }

  private String ports;
  public String getPorts() {
    return this.ports;
  }
}

