/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.example;

import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.DescriptorStore;
import org.torproject.descriptor.RelayDescriptorDownloader;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* This is a non-functional (though syntactically correct) example for how
 * the consensus-health checker could use the DescripTor API.  This class
 * will go away once the real consensus-health checker uses this API. */
public class ConsensusHealthChecker {
  public static void main(String[] args) {

    /* Create an instance of the descriptor downloader that contains all
     * the logic to download descriptors from the directory
     * authorities. */
    RelayDescriptorDownloader downloader =
        DescriptorSourceFactory.createRelayDescriptorDownloader();

    /* Make one example directory authority known to the downloader.  In
     * the real consensus-health checker, all directory authorities would
     * be added here.  (There is no list of current directory authorities
     * in the DescripTor code, because it may change over time and not all
     * DescripTor applications need to download descriptors from the
     * directory authorities.) */
    downloader.addDirectoryAuthority("gabelmoo", "212.112.245.170", 80);

    /* Tell the descriptor that we're interested in downloading the
     * current consensus from all directory authorities and all referenced
     * votes.  With these two preferences set, the downloader will try to
     * download the consensus from gabelmoo, parse it for referenced
     * votes, and try to download all of them from gabelmoo, too. */
    downloader.setIncludeCurrentConsensusFromAllDirectoryAuthorities();
    downloader.setIncludeCurrentReferencedVotes();

    /* Set a request timeout of 1 minute and a global timeout of 10
     * minutes to avoid being blocked forever by a slow download. */
    downloader.setRequestTimeout(60L * 1000L);
    downloader.setGlobalTimeout(10L * 60L * 1000L);

    /* Run the previously configured downloads.  This method call blocks
     * the main thread until all downloads have finished or the global
     * timeout has expired.  The result is a descriptor store with all
     * received descriptors. */
    DescriptorStore store = downloader.initialize();

    /* Check if all downloads have finished. */
    if (store.globalTimeoutHasExpired()) {
      System.err.println("The global timeout for downloading descriptors "
          + "has expired.  That means we're missing one or more "
          + "consensuses and/or votes and cannot make a good statement "
          + "about the consensus health.  Exiting.");
      return;
    }

    /* Go through the list of (completed and aborted) requests and tell
     * the user which of them timed out. */
    for (DescriptorRequest request : store.getDescriptorRequests()) {
      if (request.requestTimeoutHasExpired()) {
        System.out.println("The request to directory authority "
            + request.getDirectoryNickname() + " to download the "
            + "descriptor(s) at " + request.getRequestUrl() + " has "
            + "timed out.");
      }
    }

    /* Go through the list of returned consensuses.  The code to compare
     * the consensuses to each other would go here.  (In theory, we could
     * have learned about the consensuses in the request loop above, but
     * the following approach is more convenient.) */
    for (RelayNetworkStatusConsensus consensus :
        store.getAllRelayNetworkStatusConsensuses()) {
      /* Do somthing with each downloaded consensus. */
    }

    /* Also go through the list of returned votes. */
    for (RelayNetworkStatusVote vote :
        store.getAllRelayNetworkStatusVotes()) {
      /* Do somthing with each downloaded vote. */
    }

    /* That's it. */
  }
}

