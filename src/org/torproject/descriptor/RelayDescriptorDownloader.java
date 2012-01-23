/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.Iterator;
import java.util.Set;

/* Download relay descriptors from directory mirrors or authorities. */
public interface RelayDescriptorDownloader {

  /* Add a directory authority to download descriptors from.  A directory
   * authority is only required for downloading network status vote and
   * will be used when no directory mirrors are available. */
  public void addDirectoryAuthority(String nickname, String ip,
      int dirPort);

  /* Add a directory mirror to download descriptors from.  Directory
   * mirrors are preferred when downloading descriptors, except for
   * network status votes which are only available on directory
   * authorities. */
  public void addDirectoryMirror(String nickname, String ip, int dirPort);

  /* Include the current network status consensus in the downloads. */
  public void setIncludeCurrentConsensus();

  /* Include the current network status consensus in the downloads, and
   * attempt to download it from all directory authorities.  The primary
   * purpose of doing this is to compare different consensuses and
   * download characteristics to each other.  Typically, downloading from
   * a single directory mirror or authority is sufficient. */
  public void setIncludeCurrentConsensusFromAllDirectoryAuthorities();

  /* Include the current network status votes referenced from a previously
   * downloaded consensus in the downloads.  This requires downloading the
   * current consensus from at least one directory mirror or authority. */
  public void setIncludeCurrentReferencedVotes();

  /* Include the current network status vote published by the given
   * directory authority in the downloads.  This requires downloading from
   * at least one directory authority. */
  public void setIncludeCurrentVote(String fingerprint);

  /* Include the current network status votes published by the given
   * directory authorities in the downloads.  This requires downloading
   * from at least one directory authority. */
  public void setIncludeCurrentVotes(Set<String> fingerprints);

  /* Include all server descriptors referenced from a previously
   * downloaded network status consensus in the downloads. */
  public void setIncludeReferencedServerDescriptors();

  /* Exclude the server descriptor with the given identifier from the
   * downloads even if it's referenced from a consensus and we're supposed
   * to download all referenced server descriptors. */
  public void setExcludeServerDescriptor(String identifier);

  /* Exclude the server descriptors with the given identifiers from the
   * downloads even if they are referenced from a consensus and we're
   * supposed to download all referenced server descriptors. */
  public void setExcludeServerDescriptors(Set<String> identifier);

  /* Include all extra-info descriptors referenced from previously
   * downloaded server descriptors in the downloads. */
  public void setIncludeReferencedExtraInfoDescriptors();

  /* Exclude the extra-info descriptor with the given identifier from the
   * downloads even if it's referenced from a server descriptor and we're
   * supposed to download all referenced extra-info descriptors. */
  public void setExcludeExtraInfoDescriptor(String identifier);

  /* Exclude the extra-info descriptors with the given identifiers from
   * the downloads even if they are referenced from server descriptors
   * and we're supposed to download all referenced extra-info
   * descriptors. */
  public void setExcludeExtraInfoDescriptors(Set<String> identifiers);

  /* Define a connect timeout for a single request.  If a timeout expires,
   * no further requests will be sent to the directory authority or
   * mirror.  Setting this value to 0 disables the connect timeout.
   * Default value is 1 minute (60 * 1000). */
  public void setConnectTimeout(long connectTimeoutMillis);

  /* Define a read timeout for a single request.  If a timeout expires,
   * no further requests will be sent to the directory authority or
   * mirror.  Setting this value to 0 disables the read timeout.
   * Default value is 1 minute (60 * 1000). */
  public void setReadTimeout(long readTimeoutMillis);

  /* Define a global timeout for all requests.  Once this timeout expires,
   * all running requests are aborted and no further requests are made.
   * Setting this value to 0 disables the global timeout.  Default is 1
   * hour (60 * 60 * 1000). */
  public void setGlobalTimeout(long globalTimeoutMillis);

  /* Download the previously configured relay descriptors and make them
   * available via the returned blocking iterator.  Whenever the
   * downloader runs out of descriptors and expects to provide more
   * shortly after, it blocks the caller.  This method can only be run
   * once. */
  public Iterator<DescriptorRequest> downloadDescriptors();
}

