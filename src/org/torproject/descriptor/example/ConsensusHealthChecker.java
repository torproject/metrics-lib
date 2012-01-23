/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.example;

import java.util.Iterator;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.DescriptorSourceFactory;
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

    /* Set connect and read timeouts of 1 minute each and a global timeout
     * of 10 minutes to avoid being blocked forever by a slow download. */
    downloader.setConnectTimeout(60L * 1000L);
    downloader.setReadTimeout(60L * 1000L);
    downloader.setGlobalTimeout(10L * 60L * 1000L);

    /* Run the previously configured downloads and iterate over the
     * received descriptors.  Don't process them right now, but add them
     * to the checker class one by one and do the checking once all
     * downloads are complete. */
    Iterator<DescriptorRequest> descriptorRequests =
        downloader.downloadDescriptors();
    while (descriptorRequests.hasNext()) {
      DescriptorRequest request = descriptorRequests.next();
      String authority = request.getDirectoryNickname();
      long fetchTime = request.getRequestEnd()
          - request.getRequestStart();
      if (request.globalTimeoutHasExpired()) {
        System.err.println("The global timeout for downloading "
            + "descriptors has expired.  That means we're missing one or "
            + "more consensuses and/or votes and cannot make a good "
            + "statement about the consensus health.  Exiting.");
        return;
      } else if (request.connectTimeoutHasExpired() ||
          request.readTimeoutHasExpired()) {
        System.out.println("The request to directory authority "
            + request.getDirectoryNickname() + " to download the "
            + "descriptor(s) at " + request.getRequestUrl() + " has "
            + "timed out.");
      } else {
        for (Descriptor downloadedDescriptor : request.getDescriptors()) {
          if (downloadedDescriptor instanceof
              RelayNetworkStatusConsensus) {
            /* Remember that we downloaded a consensus from authority and
             * took fetchTime millis to do so. */
          } else if (downloadedDescriptor instanceof
              RelayNetworkStatusVote) {
            /* Remember that we downloaded a vote. */
          } else {
            System.err.println("Did not expect a descriptor of type "
                + downloadedDescriptor.getClass() + ".  Ignoring.");
          }
        }
      }
    }
  }
}

