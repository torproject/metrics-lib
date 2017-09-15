/* Copyright 2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.log;

/**
 * This interface provides methods for internal use only.
 *
 * @since 2.2.0
 */
public interface InternalWebServerAccessLog extends InternalLogDescriptor {

  /** The log's name should include this string. */
  public static final String MARKER = "access.log";

}

