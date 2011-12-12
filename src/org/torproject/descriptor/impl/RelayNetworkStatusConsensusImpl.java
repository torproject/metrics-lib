/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TimeZone;
import java.util.TreeMap;
import java.util.TreeSet;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.NetworkStatusEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;

/* Contains a network status consensus. */
public class RelayNetworkStatusConsensusImpl
    implements RelayNetworkStatusConsensus {

  protected static List<RelayNetworkStatusConsensus> parseConsensuses(
      byte[] consensusBytes) {
    List<RelayNetworkStatusConsensus> parsedConsensuses =
        new ArrayList<RelayNetworkStatusConsensus>();
    String startToken = "network-status-version 3";
    String splitToken = "\n" + startToken;
    String ascii = new String(consensusBytes);
    int length = consensusBytes.length, start = ascii.indexOf(startToken);
    while (start < length) {
      int end = ascii.indexOf(splitToken, start);
      if (end < 0) {
        end = length;
      } else {
        end += 1;
      }
      byte[] descBytes = new byte[end - start];
      System.arraycopy(consensusBytes, start, descBytes, 0, end - start);
      RelayNetworkStatusConsensus parsedConsensus =
          new RelayNetworkStatusConsensusImpl(descBytes);
      parsedConsensuses.add(parsedConsensus);
      start = end;
    }
    return parsedConsensuses;
  }

  protected RelayNetworkStatusConsensusImpl(byte[] consensusBytes) {
    this.consensusBytes = consensusBytes;
    this.parseConsensusBytes();
    this.checkConsistency();
    /* TODO Find a way to handle parse and consistency-check problems. */
  }

  private void parseConsensusBytes() {
    try {
      BufferedReader br = new BufferedReader(new StringReader(
          new String(this.consensusBytes)));
      String line;
      SimpleDateFormat dateTimeFormat = new SimpleDateFormat(
          "yyyy-MM-dd HH:mm:ss");
      dateTimeFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
      StringBuilder dirSourceEntryLines = null, statusEntryLines = null;
      boolean skipSignature = false;
      while ((line = br.readLine()) != null) {
        if (line.startsWith("network-status-version ")) {
          this.networkStatusVersion = Integer.parseInt(line.substring(
              "network-status-version ".length()));
        } else if (line.startsWith("vote-status ")) {
          if (!line.equals("vote-status consensus")) {
            throw new RuntimeException("Line '" + line + "' indicates "
                + "that this string is not a consensus.  Aborting "
                + "parsing.");
          }
        } else if (line.startsWith("consensus-method ")) {
          this.consensusMethod = Integer.parseInt(line.substring(
              "consensus-method ".length()));
        } else if (line.startsWith("valid-after ")) {
          this.validAfterMillis = dateTimeFormat.parse(
              line.substring("valid-after ".length())).getTime();
        } else if (line.startsWith("fresh-until ")) {
          this.freshUntilMillis = dateTimeFormat.parse(
              line.substring("fresh-until ".length())).getTime();
        } else if (line.startsWith("valid-until ")) {
          this.validUntilMillis = dateTimeFormat.parse(
              line.substring("valid-until ".length())).getTime();
        } else if (line.startsWith("voting-delay ")) {
          for (String votingDelayString : line.substring(
              "voting-delay ".length()).split(" ")) {
            this.votingDelay.add(Long.parseLong(votingDelayString));
          }
        } else if (line.startsWith("client-versions ")) {
          this.recommendedClientVersions.addAll(
              Arrays.asList(line.split(" ")[1].split(",")));
        } else if (line.startsWith("server-versions ")) {
          this.recommendedServerVersions.addAll(
              Arrays.asList(line.split(" ")[1].split(",")));
        } else if (line.startsWith("known-flags ")) {
          for (String flag : line.substring("known-flags ".length()).
              split(" ")) {
            this.knownFlags.add(flag);
          }
        } else if (line.startsWith("params ")) {
          if (line.length() > "params ".length()) {
            for (String param :
                line.substring("params ".length()).split(" ")) {
              String paramName = param.split("=")[0];
              String paramValue = param.split("=")[1];
              this.consensusParams.put(paramName, paramValue);
            }
          }
        } else if (line.startsWith("dir-source ") ||
            line.startsWith("r ") || line.equals("directory-footer")) {
          /* TODO Add code for parsing legacy dir sources. */
          if (dirSourceEntryLines != null) {
            DirSourceEntry dirSourceEntry = new DirSourceEntryImpl(
                dirSourceEntryLines.toString().getBytes());
            this.dirSourceEntries.put(dirSourceEntry.getIdentity(),
                dirSourceEntry);
            dirSourceEntryLines = null;
          }
          if (statusEntryLines != null) {
            NetworkStatusEntryImpl statusEntry =
                new NetworkStatusEntryImpl(
                statusEntryLines.toString().getBytes());
            this.statusEntries.put(statusEntry.getFingerprint(),
                statusEntry);
            statusEntryLines = null;
          }
          if (line.startsWith("dir-source ")) {
            dirSourceEntryLines = new StringBuilder();
            dirSourceEntryLines.append(line + "\n");
          } else if (line.startsWith("r ")) {
            statusEntryLines = new StringBuilder();
            statusEntryLines.append(line + "\n");
          }
        } else if (line.startsWith("contact ") ||
            line.startsWith("vote-digest ")) {
          dirSourceEntryLines.append(line + "\n");
        } else if (line.startsWith("s ") || line.equals("s") ||
            line.startsWith("v ") || line.startsWith("w ") ||
            line.startsWith("p ")) {
          statusEntryLines.append(line + "\n");
        } else if (line.startsWith("bandwidth-weights ")) {
          if (line.length() > "bandwidth-weights ".length()) {
            for (String weight : line.substring("bandwidth-weights ".
                length()).split(" ")) {
              String weightName = weight.split("=")[0];
              String weightValue = weight.split("=")[1];
              this.bandwidthWeights.put(weightName, weightValue);
            }
          }
          
        } else if (line.startsWith("directory-signature ")) {
          String[] parts = line.split(" ");
          String identity = parts[1];
          String signingKeyDigest = parts[2];
          this.directorySignatures.put(identity, signingKeyDigest);
        } else if (line.equals("-----BEGIN SIGNATURE-----")) {
          skipSignature = true;
        } else if (line.equals("-----END SIGNATURE-----")) {
          skipSignature = false;
        } else if (!skipSignature) {
          throw new RuntimeException("Unrecognized line '" + line + "'.");
        }
      }
    } catch (IOException e) {
      throw new RuntimeException("Internal error: Ran into an "
          + "IOException while parsing a String in memory.  Something's "
          + "really wrong.", e);
    } catch (ParseException e) {
      /* TODO Handle me. */
    } catch (NumberFormatException e) {
      /* TODO Handle me.  In theory, we shouldn't catch runtime
       * exceptions, but in this case it keeps the parsing code small. */
    } catch (ArrayIndexOutOfBoundsException e) {
      /* TODO Handle me.  In theory, we shouldn't catch runtime
       * exceptions, but in this case it keeps the parsing code small. */
    }
  }

  private void checkConsistency() {
    if (this.networkStatusVersion == 0) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'network-status-version' line.");
    }
    if (this.consensusMethod == 0) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'consensus-method' line.");
    }
    if (this.validAfterMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'valid-after' line.");
    }
    if (this.freshUntilMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'fresh-until' line.");
    }
    if (this.validUntilMillis == 0L) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'valid-until' line.");
    }
    if (this.votingDelay.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'voting-delay' line.");
    }
    if (this.knownFlags.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain a "
          + "'known-flags' line.");
    }
    if (this.dirSourceEntries.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain any "
          + "'dir-source' lines.");
    }
    if (this.statusEntries.isEmpty()) {
      throw new RuntimeException("Consensus doesn't contain any 'r' "
          + "lines.");
    }
  }

  private byte[] consensusBytes;
  public byte[] getRawDescriptorBytes() {
    return this.consensusBytes;
  }

  private int networkStatusVersion;
  public int getNetworkStatusVersion() {
    return this.networkStatusVersion;
  }

  private int consensusMethod;
  public int getConsensusMethod() {
    return this.consensusMethod;
  }

  private long validAfterMillis;
  public long getValidAfterMillis() {
    return this.validAfterMillis;
  }

  private long freshUntilMillis;
  public long getFreshUntilMillis() {
    return this.freshUntilMillis;
  }

  private long validUntilMillis;
  public long getValidUntilMillis() {
    return this.validUntilMillis;
  }

  private List<Long> votingDelay = new ArrayList<Long>();
  public List<Long> getVotingDelay() {
    return new ArrayList<Long>(this.votingDelay);
  }

  private SortedSet<String> recommendedClientVersions =
      new TreeSet<String>();
  public SortedSet<String> getRecommendedClientVersions() {
    return new TreeSet<String>(this.recommendedClientVersions);
  }

  private SortedSet<String> recommendedServerVersions =
      new TreeSet<String>();
  public SortedSet<String> getRecommendedServerVersions() {
    return new TreeSet<String>(this.recommendedServerVersions);
  }

  private SortedSet<String> knownFlags = new TreeSet<String>();
  public SortedSet<String> getKnownFlags() {
    return new TreeSet<String>(this.knownFlags);
  }

  private SortedMap<String, String> consensusParams =
      new TreeMap<String, String>();
  public SortedMap<String, String> getConsensusParams() {
    return new TreeMap<String, String>(this.consensusParams);
  }

  private SortedMap<String, DirSourceEntry> dirSourceEntries =
      new TreeMap<String, DirSourceEntry>();
  public SortedMap<String, DirSourceEntry> getDirSourceEntries() {
    return new TreeMap<String, DirSourceEntry>(this.dirSourceEntries);
  }

  private SortedMap<String, NetworkStatusEntry> statusEntries =
      new TreeMap<String, NetworkStatusEntry>();
  public SortedMap<String, NetworkStatusEntry> getStatusEntries() {
    return new TreeMap<String, NetworkStatusEntry>(this.statusEntries);
  }

  private SortedMap<String, String> directorySignatures =
      new TreeMap<String, String>();
  public SortedMap<String, String> getDirectorySignatures() {
    return new TreeMap<String, String>(this.directorySignatures);
  }

  private SortedMap<String, String> bandwidthWeights =
      new TreeMap<String, String>();
  public SortedMap<String, String> getBandwidthWeights() {
    return new TreeMap<String, String>(this.bandwidthWeights);
  }
}

