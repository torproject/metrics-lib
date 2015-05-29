/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;

/** Fetch descriptors from the CollecTor service available at
 * https://collector.torproject.org/ and store them to a local
 * directory. */
public interface DescriptorCollector {

  /**
   * Fetch remote files from a CollecTor instance that do not yet exist
   * locally and possibly delete local files that do not exist remotely
   * anymore.
   *
   * @param collecTorBaseUrl CollecTor base URL without trailing slash,
   * e.g., "https://collector.torproject.org".
   * @param remoteDirectories Remote directories to collect descriptors
   * from, e.g., "/recent/relay-descriptors/server-descriptors/".  Only
   * files in this directory will be collected, no files in its sub
   * directories.
   * @param minLastModified Minimum last-modified time in milliseconds of
   * files to be collected.  Set to 0 for collecting all files.
   * @param localDirectory Directory where collected files will be
   * written.
   * @param deleteExtraneousLocalFiles Whether to delete all local files
   * that do not exist remotely anymore.
   */
  public void collectDescriptors(String collecTorBaseUrl,
      String[] remoteDirectories, long minLastModified,
      File localDirectory, boolean deleteExtraneousLocalFiles);
}

