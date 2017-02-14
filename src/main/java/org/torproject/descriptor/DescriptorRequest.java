/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;

/**
 * Container for descriptors downloaded from a directory authority or
 * mirror.
 *
 * <p>When the {@link DescriptorDownloader} downloads descriptors from
 * directory authorities or mirrors it provides an iterator over these
 * containers which in turn contain references to classes implementing the
 * {@link Descriptor} interface.  This container also stores potentially
 * useful meta-data about the descriptor request.</p>
 *
 * @deprecated Removed as descriptor container together with
 *     {@link DescriptorDownloader} in favor of the much more widely used
 *     {@link DescriptorCollector}.
 *
 * @since 1.0.0
 */
public interface DescriptorRequest {

  /**
   * Return the request URL that was used in this request.
   *
   * @since 1.0.0
   */
  public String getRequestUrl();

  /**
   * Return the nickname of the directory mirror or authority as
   * previously configured.
   *
   * @since 1.0.0
   */
  public String getDirectoryNickname();

  /**
   * Return the first exception that was thrown when making this request
   * or parsing the response, or null if no exception was thrown.
   *
   * @since 1.0.0
   */
  public Exception getException();

  /**
   * Return the response code that the directory mirror or authority
   * returned.
   *
   * @since 1.0.0
   */
  public int getResponseCode();

  /**
   * Return the time in milliseconds since the epoch when this request
   * was started.
   *
   * @since 1.0.0
   */
  public long getRequestStart();

  /**
   * Return the time in milliseconds since the epoch when this request
   * ended.
   *
   * @since 1.0.0
   */
  public long getRequestEnd();

  /**
   * Return whether this request ended, because the connect timeout has
   * expired.
   *
   * @since 1.0.0
   */
  public boolean connectTimeoutHasExpired();

  /**
   * Return whether this request ended, because the read timeout has
   * expired.
   *
   * @since 1.0.0
   */
  public boolean readTimeoutHasExpired();

  /**
   * Return whether this request ended, because the global timeout for
   * all requests has expired.
   *
   * @since 1.0.0
   */
  public boolean globalTimeoutHasExpired();

  /**
   * Return the descriptors contained in the reply.
   *
   * @since 1.0.0
   */
  public List<Descriptor> getDescriptors();
}

