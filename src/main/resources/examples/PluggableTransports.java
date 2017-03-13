/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

import org.torproject.descriptor.*;

import java.io.File;
import java.util.*;

public class PluggableTransports {
  public static void main(String[] args) {

    DescriptorCollector descriptorCollector = DescriptorSourceFactory.createDescriptorCollector();
    descriptorCollector.collectDescriptors("https://collector.torproject.org", new String[] { "/recent/bridge-descriptors/extra-infos/" }, 0L, new File("descriptors"), false);

    Set<String> observedFingerprints = new HashSet<>();
    SortedMap<String, Integer> countedTransports = new TreeMap<>();

    DescriptorReader descriptorReader = DescriptorSourceFactory.createDescriptorReader();
    descriptorReader.addDirectory(new File("descriptors/recent/bridge-descriptors/extra-infos"));
    Iterator<DescriptorFile> descriptorFiles = descriptorReader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor descriptor : descriptorFile.getDescriptors()) {
        if (!(descriptor instanceof BridgeExtraInfoDescriptor)) {
          continue;
        }
        BridgeExtraInfoDescriptor extraInfo = (BridgeExtraInfoDescriptor) descriptor;
        String fingerprint = extraInfo.getFingerprint();
        if (observedFingerprints.add(fingerprint)) {
          for (String transport : extraInfo.getTransports()) {
            if (countedTransports.containsKey(transport)) {
              countedTransports.put(transport, 1 + countedTransports.get(transport));
            } else {
              countedTransports.put(transport, 1);
            }
          }
        }
      }
    }

    if (!observedFingerprints.isEmpty()) {
      double totalObservedFingerprints = observedFingerprints.size();
      for (Map.Entry<String, Integer> e : countedTransports.entrySet()) {
        System.out.printf("%20s -> %4.1f%%%n", e.getKey(), (100.0 * (double) e.getValue() / totalObservedFingerprints));
      }
    }
  }
}
