/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

/* Store meta-data about a descriptor request and a list of the returned
 * descriptors. */
public interface DescriptorRequest {

  /* Return the request URL that was used in this request. */
  public String getRequestUrl();

  /* Return the nickname of the directory mirror or authority as
   * previously configured. */
  public String getDirectoryNickname();

  /* Return the first exception that was thrown when making this request
   * or parsing the response, or null if no exception was thrown. */
  public Exception getException();

  /* Return the response code that the directory mirror or authority
   * returned. */
  public int getResponseCode();

  /* Return the time in millis when this request was started. */
  public long getRequestStart();

  /* Return the time in millis when this request ended. */
  public long getRequestEnd();

  /* Return whether this request ended, because the connect timeout has
   * expired. */
  public boolean connectTimeoutHasExpired();

  /* Return whether this request ended, because the read timeout has
   * expired. */
  public boolean readTimeoutHasExpired();

  /* Return whether this request ended, because the global timeout for all
   * requests has expired. */
  public boolean globalTimeoutHasExpired();

  /* Return the descriptors contained in the reply. */
  public List<Descriptor> getDescriptors();
}

