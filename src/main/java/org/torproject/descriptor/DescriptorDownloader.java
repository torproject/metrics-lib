/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.Iterator;
import java.util.Set;

/**
 * Descriptor source that downloads relay descriptors from directory
 * authorities or mirrors.
 *
 * <p>Downloading descriptors is done in a batch which starts after
 * setting any configuration options and initiating the download
 * process.</p>
 *
 * @since 1.0.0
 */
public interface DescriptorDownloader {

  /**
   * Add a directory authority to download descriptors from, which is
   * only required for downloading network status votes and will be used
   * when no directory mirrors are available.
   *
   * @since 1.0.0
   */
  public void addDirectoryAuthority(String nickname, String ip,
      int dirPort);

  /**
   * Add a directory mirror to download descriptors from, which is
   * preferred for downloading descriptors, except for network status
   * votes which are only available on directory authorities.
   *
   * @since 1.0.0
   */
  public void addDirectoryMirror(String nickname, String ip, int dirPort);

  /**
   * Include the current network status consensus in the downloads.
   *
   * @since 1.0.0
   */
  public void setIncludeCurrentConsensus();

  /**
   * Include the current network status consensus in the downloads, and
   * attempt to download it from all directory authorities.
   *
   * <p>The primary purpose of doing this is to compare different
   * consensuses and download characteristics to each other.  Typically,
   * downloading from a single directory mirror or authority is
   * sufficient.</p>
   *
   * @since 1.0.0
   */
  public void setIncludeCurrentConsensusFromAllDirectoryAuthorities();

  /**
   * Include the current network status votes referenced from a
   * previously downloaded consensus in the downloads, which requires
   * downloading the current consensus from at least one directory mirror
   * or authority.
   *
   * @since 1.0.0
   */
  public void setIncludeCurrentReferencedVotes();

  /**
   * Include the current network status vote published by the given
   * directory authority in the downloads, which requires downloading from
   * at least one directory authority.
   *
   * @since 1.0.0
   */
  public void setIncludeCurrentVote(String fingerprint);

  /**
   * Include the current network status votes published by the given
   * directory authorities in the downloads, which requires downloading
   * from at least one directory authority.
   *
   * @since 1.0.0
   */
  public void setIncludeCurrentVotes(Set<String> fingerprints);

  /**
   * Include all server descriptors referenced from a previously
   * downloaded network status consensus in the downloads.
   *
   * @since 1.0.0
   */
  public void setIncludeReferencedServerDescriptors();

  /**
   * Exclude the server descriptor with the given identifier from the
   * downloads even if it's referenced from a consensus and we're supposed
   * to download all referenced server descriptors.
   *
   * @since 1.0.0
   */
  public void setExcludeServerDescriptor(String identifier);

  /**
   * Exclude the server descriptors with the given identifiers from the
   * downloads even if they are referenced from a consensus and we're
   * supposed to download all referenced server descriptors.
   *
   * @since 1.0.0
   */
  public void setExcludeServerDescriptors(Set<String> identifier);

  /**
   * Include all extra-info descriptors referenced from previously
   * downloaded server descriptors in the downloads.
   *
   * @since 1.0.0
   */
  public void setIncludeReferencedExtraInfoDescriptors();

  /**
   * Exclude the extra-info descriptor with the given identifier from the
   * downloads even if it's referenced from a server descriptor and we're
   * supposed to download all referenced extra-info descriptors.
   *
   * @since 1.0.0
   */
  public void setExcludeExtraInfoDescriptor(String identifier);

  /**
   * Exclude the extra-info descriptors with the given identifiers from
   * the downloads even if they are referenced from server descriptors
   * and we're supposed to download all referenced extra-info
   * descriptors.
   *
   * @since 1.0.0
   */
  public void setExcludeExtraInfoDescriptors(Set<String> identifiers);

  /**
   * Define a connect timeout for a single request.
   *
   * <p>If a timeout expires, no further requests will be sent to the
   * directory authority or mirror.  Setting this value to 0 disables the
   * connect timeout.  Default value is 1 minute (60 * 1000).</p>
   *
   * @since 1.0.0
   */
  public void setConnectTimeout(long connectTimeoutMillis);

  /**
   * Define a read timeout for a single request.
   *
   * <p>If a timeout expires, no further requests will be sent to the
   * directory authority or mirror.  Setting this value to 0 disables the
   * read timeout.  Default value is 1 minute (60 * 1000).</p>
   *
   * @since 1.0.0
   */
  public void setReadTimeout(long readTimeoutMillis);

  /**
   * Define a global timeout for all requests.
   *
   * <p>Once this timeout expires, all running requests are aborted and no
   * further requests are made.  Setting this value to 0 disables the
   * global timeout.  Default is 1 hour (60 * 60 * 1000).</p>
   *
   * @since 1.0.0
   */
  public void setGlobalTimeout(long globalTimeoutMillis);

  /**
   * Fail descriptor parsing when encountering an unrecognized line.
   *
   * <p>This option is not set by default, because the Tor specifications
   * allow for new lines to be added that shall be ignored by older Tor
   * versions.  But some applications may want to handle unrecognized
   * descriptor lines explicitly.</p>
   *
   * @since 1.0.0
   */
  public void setFailUnrecognizedDescriptorLines();

  /**
   * Download the previously configured relay descriptors and make them
   * available via the returned blocking iterator.
   *
   * <p>Whenever the downloader runs out of descriptors and expects to
   * provide more shortly after, it blocks the caller.  This method can
   * only be run once.</p>
   *
   * @since 1.0.0
   */
  public Iterator<DescriptorRequest> downloadDescriptors();
}

