/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.Iterator;
import java.util.Set;
import org.torproject.descriptor.DescriptorRequest;
import org.torproject.descriptor.RelayDescriptorDownloader;

public class RelayDescriptorDownloaderImpl
    implements RelayDescriptorDownloader {

  public void addDirectoryAuthority(String nickname, String ip,
      int dirPort) {
    /* TODO Implement me. */
  }

  public void addDirectoryMirror(String nickname, String ip,
      int dirPort) {
    /* TODO Implement me. */
  }

  public void setIncludeCurrentConsensus() {
    /* TODO Implement me. */
  }

  public void setIncludeCurrentConsensusFromAllDirectoryAuthorities() {
    /* TODO Implement me. */
  }

  public void setIncludeCurrentReferencedVotes() {
    /* TODO Implement me. */
  }

  public void setIncludeCurrentVote(String fingerprint) {
    /* TODO Implement me. */
  }

  public void setIncludeCurrentVotes(Set<String> fingerprints) {
    /* TODO Implement me. */
  }

  public void setIncludeReferencedServerDescriptors() {
    /* TODO Implement me. */
  }

  public void setExcludeServerDescriptor(String identifier) {
    /* TODO Implement me. */
  }

  public void setExcludeServerDescriptors(Set<String> identifier) {
    /* TODO Implement me. */
  }

  public void setIncludeReferencedExtraInfoDescriptors() {
    /* TODO Implement me. */
  }

  public void setExcludeExtraInfoDescriptor(String identifier) {
    /* TODO Implement me. */
  }

  public void setExcludeExtraInfoDescriptors(Set<String> identifiers) {
    /* TODO Implement me. */
  }

  public void setRequestTimeout(long requestTimeoutMillis) {
    /* TODO Implement me. */
  }

  public void setGlobalTimeout(long globalTimeoutMillis) {
    /* TODO Implement me. */
  }

  public Iterator<DescriptorRequest> downloadDescriptors() {
    /* TODO Implement me. */
    return new BlockingIteratorImpl<DescriptorRequest>();
  }
}

