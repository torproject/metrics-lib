/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.List;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.zip.InflaterInputStream;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.DirSourceEntry;
import org.torproject.descriptor.RelayDescriptorDownloader;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* TODO Should this class be split up and be moved to its own subpackage?
 * It's huge, and it's not going to get smaller in the future. */
public class RelayDescriptorDownloaderImpl
    implements RelayDescriptorDownloader {

  /* TODO Move part of the factory class to the impl package and make this
   * constructor protected. */
  public RelayDescriptorDownloaderImpl() {
  }

  private boolean hasStartedDownloading = false;
  private boolean hasFinishedDownloading = false;

  private BlockingIteratorImpl<DescriptorRequest> descriptorQueue =
      new BlockingIteratorImpl<DescriptorRequest>();

  private SortedMap<String, DirectoryDownloader> directoryAuthorities =
      new TreeMap<String, DirectoryDownloader>();
  public void addDirectoryAuthority(String nickname, String ip,
      int dirPort) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkDirectoryParameters(nickname, ip, dirPort);
    DirectoryDownloader directoryAuthority = new DirectoryDownloader(
        nickname, ip, dirPort, this);
    this.directoryAuthorities.put(nickname, directoryAuthority);
  }

  private SortedMap<String, DirectoryDownloader> directoryMirrors =
      new TreeMap<String, DirectoryDownloader>();
  public void addDirectoryMirror(String nickname, String ip,
      int dirPort) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkDirectoryParameters(nickname, ip, dirPort);
    DirectoryDownloader directoryMirror = new DirectoryDownloader(
        nickname, ip, dirPort, this);
    this.directoryMirrors.put(nickname, directoryMirror);
    /* TODO Implement prioritizing mirrors for non-vote downloads. */
    throw new UnsupportedOperationException("Prioritizing directory "
        + "mirrors over directory authorities is not implemented yet.  "
        + "Until it is, configuring directory mirrors is misleading and "
        + "therefore not supported.");
  }

  private void checkDirectoryParameters(String nickname, String ip,
      int dirPort) {
    if (nickname == null || nickname.length() < 1) {
      throw new IllegalArgumentException("'" + nickname + "' is not a "
          + "valid nickname.");
    }
    if (ip == null || ip.length() < 7 || ip.split("\\.").length != 4) {
      throw new IllegalArgumentException("'" + ip + "' is not a valid IP "
          + "address.");
    }
    if (dirPort < 1 || dirPort > 65535) {
      throw new IllegalArgumentException(String.valueOf(dirPort) + " is "
          + "not a valid DirPort.");
    }
    /* TODO Relax the requirement for directory nicknames to be unique.
     * In theory, we can identify them by ip+port. */
    if (this.directoryAuthorities.containsKey(nickname) ||
        this.directoryMirrors.containsKey(nickname)) {
      throw new IllegalArgumentException("Directory nicknames must be "
          + "unique.");
    }
  }

  public void setIncludeCurrentConsensus() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.missingConsensus = true;
  }

  private boolean downloadConsensusFromAllAuthorities = false;
  public void setIncludeCurrentConsensusFromAllDirectoryAuthorities() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.downloadConsensusFromAllAuthorities = true;
  }

  private boolean includeCurrentReferencedVotes = false;
  public void setIncludeCurrentReferencedVotes() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.includeCurrentReferencedVotes = true;
  }

  public void setIncludeCurrentVote(String fingerprint) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkVoteFingerprint(fingerprint);
    this.missingVotes.add(fingerprint);
  }

  public void setIncludeCurrentVotes(Set<String> fingerprints) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    if (fingerprints == null) {
      throw new IllegalArgumentException("Set of fingerprints must not "
          + "be null.");
    }
    for (String fingerprint : fingerprints) {
      this.checkVoteFingerprint(fingerprint);
    }
    for (String fingerprint : fingerprints) {
      this.setIncludeCurrentVote(fingerprint);
    }
  }

  private void checkVoteFingerprint(String fingerprint) {
    if (fingerprint == null || fingerprint.length() != 40) {
      throw new IllegalArgumentException("'" + fingerprint + "' is not a "
          + "valid fingerprint.");
    }
  }

  public void setIncludeReferencedServerDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  public void setExcludeServerDescriptor(String identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  public void setExcludeServerDescriptors(Set<String> identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  public void setIncludeReferencedExtraInfoDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  public void setExcludeExtraInfoDescriptor(String identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  public void setExcludeExtraInfoDescriptors(Set<String> identifiers) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  private long requestTimeoutMillis = 60L * 1000L;
  public void setRequestTimeout(long requestTimeoutMillis) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    if (requestTimeoutMillis < 0L) {
      throw new IllegalArgumentException("Request timeout value "
          + String.valueOf(requestTimeoutMillis) + " may not be "
          + "negative.");
    }
    this.requestTimeoutMillis = requestTimeoutMillis;
  }

  private long globalTimeoutMillis = 60L * 60L * 1000L;
  public void setGlobalTimeout(long globalTimeoutMillis) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    if (globalTimeoutMillis < 0L) {
      throw new IllegalArgumentException("Global timeout value "
          + String.valueOf(globalTimeoutMillis) + " may not be "
          + "negative.");
    }
    this.globalTimeoutMillis = globalTimeoutMillis;
  }

  public Iterator<DescriptorRequest> downloadDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Initiating downloads is only "
          + "permitted once.");
    }
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
        directoryMirror.downloadCoordinator = this;
        new Thread(directoryMirror).start();
      }
      for (DirectoryDownloader directoryAuthority :
          this.directoryAuthorities.values()) {
        directoryAuthority.downloadCoordinator = this;
        new Thread(directoryAuthority).start();
      }
    }
    return this.descriptorQueue;
  }

  /* Interrupt all downloads if the total download time exceeds a given
   * time. */
  private Thread globalTimerThread;
  private static class GlobalTimer implements Runnable {
    private long timeoutMillis;
    private RelayDescriptorDownloaderImpl downloadCoordinator;
    private GlobalTimer(long timeoutMillis,
        RelayDescriptorDownloaderImpl downloadCoordinator) {
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

  /* TODO This whole download logic is a mess.  It should probably go to
   * its own class, and it needs a cleanup. */

  /* Are we missing the consensus, and should the next directory that
   * hasn't tried downloading it before attempt to download it? */
  private boolean missingConsensus = false;

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

  /* Look up what request a directory should make next.  If there is
   * nothing to do right now, but maybe later, block the caller.  If
   * we're done downloading, return null to notify the caller. */
  private synchronized DescriptorRequestImpl createRequest(
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
  private synchronized void deliverResponse(
      DescriptorRequestImpl response) {
    String nickname = response.getDirectoryNickname();
    if (response.getDescriptorType().equals("consensus")) {
      if (response.getResponseCode() == 200) {
        List<RelayNetworkStatusConsensus> parsedConsensuses =
            RelayNetworkStatusConsensusImpl.parseConsensuses(
            response.getResponseBytes());
        List<Descriptor> parsedDescriptors =
            new ArrayList<Descriptor>(parsedConsensuses);
        response.setDescriptors(parsedDescriptors);
        if (this.includeCurrentReferencedVotes) {
          /* TODO Only add votes if the consensus is not older than one
           * hour.  Or does that make no sense? */
          for (RelayNetworkStatusConsensus parsedConsensus :
              parsedConsensuses) {
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
      if (response.getResponseCode() == 200) {
        List<RelayNetworkStatusVote> parsedVotes =
            RelayNetworkStatusVoteImpl.parseVotes(
            response.getResponseBytes());
        List<Descriptor> parsedDescriptors =
            new ArrayList<Descriptor>(parsedVotes);
        response.setDescriptors(parsedDescriptors);
      } else {
        this.missingVotes.add(requestedVote);
      }
    }
    this.descriptorQueue.add(response);
    if ((!this.missingConsensus ||
        (this.downloadConsensusFromAllAuthorities &&
        this.requestedConsensuses.containsAll(
        this.directoryAuthorities.keySet()))) &&
        this.missingVotes.isEmpty() &&
        this.requestingVotes.isEmpty()) {
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

  /* Download descriptors from one directory authority or mirror.  First,
   * ask the coordinator thread to create a request, run it, and deliver
   * the response.  Repeat until the coordinator thread says there are no
   * further requests to make. */
  private static class DirectoryDownloader implements Runnable {
    private String nickname;
    private String ipPort;
    private RelayDescriptorDownloaderImpl downloadCoordinator;
    private DirectoryDownloader(String nickname, String ip, int dirPort,
        RelayDescriptorDownloaderImpl downloadCoordinator) {
      this.nickname = nickname;
      this.ipPort = ip + ":" + String.valueOf(dirPort);
      this.downloadCoordinator = downloadCoordinator;
    }
    private long requestTimeout;
    private void setRequestTimeout(long requestTimeout) {
      this.requestTimeout = requestTimeout;
    }
    public void run() {
      DescriptorRequestImpl request = null;
      do {
        request = this.downloadCoordinator.createRequest(this.nickname);
        if (request != null) {
          String url = "http://" + this.ipPort
              + request.getRequestedResource();
          request.setRequestStart(System.currentTimeMillis());
          Thread timeoutThread = new Thread(new RequestTimeout(
              this.requestTimeout));
          timeoutThread.start();
          try {
            URL u = new URL(url);
            HttpURLConnection huc =
                (HttpURLConnection) u.openConnection();
            huc.setRequestMethod("GET");
            huc.connect();
            int responseCode = huc.getResponseCode();
            request.setResponseCode(responseCode);
            if (responseCode == 200) {
              BufferedInputStream in = new BufferedInputStream(
                  new InflaterInputStream(huc.getInputStream()));
              ByteArrayOutputStream baos = new ByteArrayOutputStream();
              int len;
              byte[] data = new byte[1024];
              while ((len = in.read(data, 0, 1024)) >= 0) {
                baos.write(data, 0, len);
              }
              in.close();
              byte[] responseBytes = baos.toByteArray();
              request.setResponseBytes(responseBytes);
              request.setRequestEnd(System.currentTimeMillis());
            }
          } catch (IOException e) {
            /* TODO Should we print out a warning or something? */
            e.printStackTrace();
            break;
          }
          /* TODO How do we find out if we were interrupted, and by who?
           * Set the request or global timeout flag in the response. */
          timeoutThread.interrupt();
          this.downloadCoordinator.deliverResponse(request);
        }
      } while (request != null);
    }
  }

  /* Interrupt a download request if it takes longer than a given time. */
  private static class RequestTimeout implements Runnable {
    private long timeoutMillis;
    private Thread downloaderThread;
    private RequestTimeout(long timeoutMillis) {
      this.downloaderThread = Thread.currentThread();
      this.timeoutMillis = timeoutMillis;
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
      this.downloaderThread.interrupt();
    }
  }
}

