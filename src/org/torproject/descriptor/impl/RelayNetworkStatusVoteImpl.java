/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* Contains a network status vote. */
/* TODO This class doesn't contain any parsing code yet, and it would be
 * sharing a lot of that code with the consensus class.  Should there be
 * an abstract super class for the two? */
public class RelayNetworkStatusVoteImpl
    implements RelayNetworkStatusVote {

  protected static List<RelayNetworkStatusVote> parseVotes(
      byte[] voteBytes) {
    List<RelayNetworkStatusVote> parsedVotes =
        new ArrayList<RelayNetworkStatusVote>();
    String startToken = "network-status-version 3";
    String splitToken = "\n" + startToken;
    String ascii = new String(voteBytes);
    int length = voteBytes.length, start = ascii.indexOf(startToken);
    while (start < length) {
      int end = ascii.indexOf(splitToken, start);
      if (end < 0) {
        end = length;
      } else {
        end += 1;
      }
      byte[] descBytes = new byte[end - start];
      System.arraycopy(voteBytes, start, descBytes, 0, end - start);
      RelayNetworkStatusVote parsedVote =
          new RelayNetworkStatusVoteImpl(descBytes);
      parsedVotes.add(parsedVote);
      start = end;
    }
    return parsedVotes;
  }

  protected RelayNetworkStatusVoteImpl(byte[] voteBytes) {
    this.voteBytes = voteBytes;
  }

  private byte[] voteBytes;
  public byte[] getRawDescriptorBytes() {
    return this.voteBytes;
  }
}

