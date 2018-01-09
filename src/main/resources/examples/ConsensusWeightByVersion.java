/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

import org.torproject.descriptor.*;

import java.io.File;
import java.util.*;

public class ConsensusWeightByVersion {
  public static void main(String[] args) {

    // Download consensuses.
    DescriptorCollector descriptorCollector = DescriptorSourceFactory.createDescriptorCollector();
    descriptorCollector.collectDescriptors("https://collector.torproject.org", new String[] { "/recent/relay-descriptors/consensuses/" }, 0L, new File("descriptors"), false);

    // Keep local counters for extracted descriptor data.
    long totalBandwidth = 0L;
    SortedMap<String, Long> bandwidthByVersion = new TreeMap<>();

    // Read descriptors from disk.
    DescriptorReader descriptorReader = DescriptorSourceFactory.createDescriptorReader();
    for (Descriptor descriptor : descriptorReader.readDescriptors(new File("descriptors/recent/relay-descriptors/consensuses"))) {
      if (!(descriptor instanceof RelayNetworkStatusConsensus)) {
        // We're only interested in consensuses.
        continue;
      }
      RelayNetworkStatusConsensus consensus = (RelayNetworkStatusConsensus) descriptor;
      for (NetworkStatusEntry entry : consensus.getStatusEntries().values()) {
        String version = entry.getVersion();
        if (!version.startsWith("Tor ") || version.length() < 9) {
          // We're only interested in a.b.c type versions for this example.
          continue;
        }
        // Remove the 'Tor ' prefix and anything starting at the patch level.
        version = version.substring(4, 9);
        long bandwidth = entry.getBandwidth();
        totalBandwidth += bandwidth;
        if (bandwidthByVersion.containsKey(version)) {
          bandwidthByVersion.put(version, bandwidth + bandwidthByVersion.get(version));
        } else {
          bandwidthByVersion.put(version, bandwidth);
        }
      }
    }

    // Print out fractions of consensus weight by Tor version.
    if (totalBandwidth > 0L) {
      for (Map.Entry<String, Long> e : bandwidthByVersion.entrySet()) {
        System.out.printf("%s -> %4.1f%%%n", e.getKey(), (100.0 * (double) e.getValue() / (double) totalBandwidth));
      }
    }
  }
}
