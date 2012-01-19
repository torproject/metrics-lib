/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* TODO This whole download logic is a mess and needs a cleanup. */
public class DownloadCoordinatorImpl implements DownloadCoordinator {

  private BlockingIteratorImpl<DescriptorRequest> descriptorQueue =
      new BlockingIteratorImpl<DescriptorRequest>();
  protected Iterator<DescriptorRequest> getDescriptorQueue() {
    return this.descriptorQueue;
  }

  private SortedMap<String, DirectoryDownloader> directoryAuthorities;
  private SortedMap<String, DirectoryDownloader> directoryMirrors;
  private boolean downloadConsensusFromAllAuthorities;
  private boolean includeCurrentReferencedVotes;
  private long requestTimeoutMillis;
  private long globalTimeoutMillis;

  protected DownloadCoordinatorImpl(
      SortedMap<String, DirectoryDownloader> directoryAuthorities,
      SortedMap<String, DirectoryDownloader> directoryMirrors,
      boolean downloadConsensus,
      boolean downloadConsensusFromAllAuthorities,
      Set<String> downloadVotes, boolean includeCurrentReferencedVotes,
      long requestTimeoutMillis, long globalTimeoutMillis) {
    this.directoryAuthorities = directoryAuthorities;
    this.directoryMirrors = directoryMirrors;
    this.missingConsensus = downloadConsensus;
    this.downloadConsensusFromAllAuthorities =
        downloadConsensusFromAllAuthorities;
    this.missingVotes = downloadVotes;
    this.includeCurrentReferencedVotes = includeCurrentReferencedVotes;
    this.requestTimeoutMillis = requestTimeoutMillis;
    this.globalTimeoutMillis = globalTimeoutMillis;
    if (this.directoryMirrors.isEmpty() &&
        this.directoryAuthorities.isEmpty()) {
      this.descriptorQueue.setOutOfDescriptors();
      /* TODO Should we say anything if we don't have any directories
       * configured? */
    } else {
      GlobalTimer globalTimer = new GlobalTimer(this.globalTimeoutMillis,
          this);
      this.globalTimerThread = new Thread(globalTimer);
      this.globalTimerThread.start();
      for (DirectoryDownloader directoryMirror :
          this.directoryMirrors.values()) {
        directoryMirror.setDownloadCoordinator(this);
        directoryMirror.setRequestTimeout(this.requestTimeoutMillis);
        new Thread(directoryMirror).start();
      }
      for (DirectoryDownloader directoryAuthority :
          this.directoryAuthorities.values()) {
        directoryAuthority.setDownloadCoordinator(this);
        directoryAuthority.setRequestTimeout(this.requestTimeoutMillis);
        new Thread(directoryAuthority).start();
      }
    }
  }

  /* Interrupt all downloads if the total download time exceeds a given
   * time. */
  private Thread globalTimerThread;
  private static class GlobalTimer implements Runnable {
    private long timeoutMillis;
    private DownloadCoordinatorImpl downloadCoordinator;
    private GlobalTimer(long timeoutMillis,
        DownloadCoordinatorImpl downloadCoordinator) {
      this.timeoutMillis = timeoutMillis;
      this.downloadCoordinator = downloadCoordinator;
    }
    public void run() {
      long started = System.currentTimeMillis(), sleep;
      while ((sleep = started + this.timeoutMillis
          - System.currentTimeMillis()) > 0L) {
        try {
          Thread.sleep(sleep);
        } catch (InterruptedException e) {
          return;
        }
      }
      this.downloadCoordinator.interruptAllDownloads();
    }
  }

  /* Are we missing the consensus, and should the next directory that
   * hasn't tried downloading it before attempt to download it? */
  private boolean missingConsensus = false;

  /* Which directories are currently attempting to download the
   * consensus? */
  private Set<String> requestingConsensuses = new HashSet<String>();

  /* Which directories have attempted to download the consensus so far,
   * including those directories that are currently attempting it? */
  private Set<String> requestedConsensuses = new HashSet<String>();

  /* Which votes are we currently missing? */
  private Set<String> missingVotes = new HashSet<String>();

  /* Which vote (map value) is a given directory (map key) currently
   * attempting to download? */
  private Map<String, String> requestingVotes =
      new HashMap<String, String>();

  /* Which votes (map value) has a given directory (map key) attempted or
   * is currently attempting to download? */
  private Map<String, Set<String>> requestedVotes =
      new HashMap<String, Set<String>>();

  private boolean hasFinishedDownloading = false;

  /* Look up what request a directory should make next.  If there is
   * nothing to do right now, but maybe later, block the caller.  If
   * we're done downloading, return null to notify the caller. */
  public synchronized DescriptorRequestImpl createRequest(
      String nickname) {
    while (!this.hasFinishedDownloading) {
      DescriptorRequestImpl request = new DescriptorRequestImpl();
      request.setDirectoryNickname(nickname);
      if ((this.missingConsensus ||
          (this.downloadConsensusFromAllAuthorities &&
          this.directoryAuthorities.containsKey(nickname))) &&
          !this.requestedConsensuses.contains(nickname)) {
        if (!this.downloadConsensusFromAllAuthorities) {
          this.missingConsensus = false;
        }
        this.requestingConsensuses.add(nickname);
        this.requestedConsensuses.add(nickname);
        request.setRequestedResource(
            "/tor/status-vote/current/consensus.z");
        request.setDescriptorType("consensus");
        return request;
      }
      if (!this.missingVotes.isEmpty() &&
          this.directoryAuthorities.containsKey(nickname)) {
        String requestingVote = null;
        for (String missingVote : this.missingVotes) {
          if (!this.requestedVotes.containsKey(nickname) ||
              !this.requestedVotes.get(nickname).contains(missingVote)) {
            requestingVote = missingVote;
          }
        }
        if (requestingVote != null) {
          this.requestingVotes.put(nickname, requestingVote);
          if (!this.requestedVotes.containsKey(nickname)) {
            this.requestedVotes.put(nickname, new HashSet<String>());
          }
          this.requestedVotes.get(nickname).add(requestingVote);
          this.missingVotes.remove(requestingVote);
          request.setRequestedResource("/tor/status-vote/current/"
              + requestingVote + ".z");
          request.setDescriptorType("vote");
          return request;
        }
      }
      /* TODO Add server descriptors and extra-info descriptors later. */
      try {
        this.wait();
      } catch (InterruptedException e) {
        /* TODO What shall we do? */
      }
    }
    return null;
  }

  /* Deliver a response which may either contain one or more descriptors
   * or a failure response code.  Update the lists of missing descriptors,
   * decide if there are more descriptors to download, and wake up any
   * waiting downloader threads. */
  public synchronized void deliverResponse(
      DescriptorRequestImpl response) {
    String nickname = response.getDirectoryNickname();
    if (response.getDescriptorType().equals("consensus")) {
      this.requestingConsensuses.remove(nickname);
      if (response.getResponseCode() == 200) {
        if (this.includeCurrentReferencedVotes) {
          /* TODO Only add votes if the consensus is not older than one
           * hour.  Or does that make no sense? */
          for (Descriptor parsedDescriptor : response.getDescriptors()) {
            if (!(parsedDescriptor instanceof
                RelayNetworkStatusConsensus)) {
              continue;
            }
            RelayNetworkStatusConsensus parsedConsensus =
                (RelayNetworkStatusConsensus) parsedDescriptor;
            for (DirSourceEntry dirSource :
                parsedConsensus.getDirSourceEntries().values()) {
              String identity = dirSource.getIdentity();
              if (!this.missingVotes.contains(identity)) {
                boolean alreadyRequested = false;
                for (Set<String> requestedBefore :
                    this.requestedVotes.values()) {
                  if (requestedBefore.contains(identity)) {
                    alreadyRequested = true;
                    break;
                  }
                }
                if (!alreadyRequested) {
                  this.missingVotes.add(identity);
                }
              }
            }
          }
          /* TODO Later, add referenced server descriptors. */
        }
      } else {
        this.missingConsensus = true;
      }
    } else if (response.getDescriptorType().equals("vote")) {
      String requestedVote = requestingVotes.remove(nickname);
      if (response.getResponseCode() != 200) {
        this.missingVotes.add(requestedVote);
      }
    }
    if (response.getRequestEnd() != 0L) {
      this.descriptorQueue.add(response);
    }
    if ((!this.missingConsensus ||
        (this.downloadConsensusFromAllAuthorities &&
        this.requestedConsensuses.containsAll(
        this.directoryAuthorities.keySet()) &&
        this.requestingConsensuses.isEmpty())) &&
        this.missingVotes.isEmpty() &&
        this.requestingVotes.isEmpty()) {
      /* TODO This logic may be somewhat broken.  We don't wait for all
       * consensus requests to complete or fail, which results in adding
       * (failed) requests to the queue when we think we're done. */
      this.hasFinishedDownloading = true;
      this.globalTimerThread.interrupt();
      this.descriptorQueue.setOutOfDescriptors();
    }
    /* Wake up all waiting downloader threads.  Maybe they can now
     * download something, or they'll realize we're done downloading. */
    this.notifyAll();
  }

  private synchronized void interruptAllDownloads() {
    this.hasFinishedDownloading = true;
    this.notifyAll();
  }
}

