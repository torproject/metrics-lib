/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorDownloader;
import org.torproject.descriptor.DescriptorRequest;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

public class DescriptorDownloaderImpl
    implements DescriptorDownloader {

  private boolean hasStartedDownloading = false;

  private SortedMap<String, DirectoryDownloader> directoryAuthorities =
      new TreeMap<>();

  @Override
  public void addDirectoryAuthority(String nickname, String ip,
      int dirPort) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkDirectoryParameters(nickname, ip, dirPort);
    DirectoryDownloader directoryAuthority = new DirectoryDownloader(
        nickname, ip, dirPort);
    this.directoryAuthorities.put(nickname, directoryAuthority);
  }

  private SortedMap<String, DirectoryDownloader> directoryMirrors =
      new TreeMap<>();

  @Override
  public void addDirectoryMirror(String nickname, String ip,
      int dirPort) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkDirectoryParameters(nickname, ip, dirPort);
    DirectoryDownloader directoryMirror = new DirectoryDownloader(
        nickname, ip, dirPort);
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
    if (this.directoryAuthorities.containsKey(nickname)
        || this.directoryMirrors.containsKey(nickname)) {
      throw new IllegalArgumentException("Directory nicknames must be "
          + "unique.");
    }
  }

  private boolean downloadConsensus = false;

  @Override
  public void setIncludeCurrentConsensus() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.downloadConsensus = true;
  }

  private boolean downloadConsensusFromAllAuthorities = false;

  @Override
  public void setIncludeCurrentConsensusFromAllDirectoryAuthorities() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.downloadConsensusFromAllAuthorities = true;
  }

  private boolean includeCurrentReferencedVotes = false;

  @Override
  public void setIncludeCurrentReferencedVotes() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.includeCurrentReferencedVotes = true;
  }

  private Set<String> downloadVotes = new HashSet<>();

  @Override
  public void setIncludeCurrentVote(String fingerprint) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.checkVoteFingerprint(fingerprint);
    this.downloadVotes.add(fingerprint);
  }

  @Override
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

  @Override
  public void setIncludeReferencedServerDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  @Override
  public void setExcludeServerDescriptor(String identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  @Override
  public void setExcludeServerDescriptors(Set<String> identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading server "
        + "descriptors is not implemented yet.");
  }

  @Override
  public void setIncludeReferencedExtraInfoDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  @Override
  public void setExcludeExtraInfoDescriptor(String identifier) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  @Override
  public void setExcludeExtraInfoDescriptors(Set<String> identifiers) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    /* TODO Implement me. */
    throw new UnsupportedOperationException("Downloading extra-info "
        + "descriptors is not implemented yet.");
  }

  private long readTimeoutMillis = 60L * 1000L;

  @Override
  public void setReadTimeout(long readTimeoutMillis) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    if (readTimeoutMillis < 0L) {
      throw new IllegalArgumentException("Read timeout value "
          + String.valueOf(readTimeoutMillis) + " may not be "
          + "negative.");
    }
    this.readTimeoutMillis = readTimeoutMillis;
  }

  private long connectTimeoutMillis = 60L * 1000L;

  @Override
  public void setConnectTimeout(long connectTimeoutMillis) {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    if (connectTimeoutMillis < 0L) {
      throw new IllegalArgumentException("Connect timeout value "
          + String.valueOf(connectTimeoutMillis) + " may not be "
          + "negative.");
    }
    this.connectTimeoutMillis = connectTimeoutMillis;
  }

  private long globalTimeoutMillis = 60L * 60L * 1000L;

  @Override
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

  private boolean failUnrecognizedDescriptorLines = false;

  @Override
  public void setFailUnrecognizedDescriptorLines() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to download.");
    }
    this.failUnrecognizedDescriptorLines = true;
  }

  @Override
  public Iterator<DescriptorRequest> downloadDescriptors() {
    if (this.hasStartedDownloading) {
      throw new IllegalStateException("Initiating downloads is only "
          + "permitted once.");
    }
    this.hasStartedDownloading = true;
    DownloadCoordinatorImpl downloadCoordinator =
        new DownloadCoordinatorImpl(this.directoryAuthorities,
        this.directoryMirrors, this.downloadConsensus,
        this.downloadConsensusFromAllAuthorities, this.downloadVotes,
        this.includeCurrentReferencedVotes, this.connectTimeoutMillis,
        this.readTimeoutMillis, this.globalTimeoutMillis,
        this.failUnrecognizedDescriptorLines);
    Iterator<DescriptorRequest> descriptorQueue = downloadCoordinator
        .getDescriptorQueue();
    return descriptorQueue;
  }
}

