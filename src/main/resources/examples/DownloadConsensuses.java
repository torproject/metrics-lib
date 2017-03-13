/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

import org.torproject.descriptor.*;

import java.io.File;

public class DownloadConsensuses {
  public static void main(String[] args) {

    // Download consensuses published in the last 72 hours, which will take up to five minutes and require several hundred MB on the local disk.
    DescriptorCollector descriptorCollector = DescriptorSourceFactory.createDescriptorCollector();
    descriptorCollector.collectDescriptors(
        // Download from Tor's main CollecTor instance,
        "https://collector.torproject.org",
        // include only network status consensuses
        new String[] { "/recent/relay-descriptors/consensuses/" },
        // regardless of last-modified time,
        0L,
        // write to the local directory called descriptors/,
        new File("descriptors"),
        // and don't delete extraneous files that do not exist remotely anymore.
        false);
  }
}
