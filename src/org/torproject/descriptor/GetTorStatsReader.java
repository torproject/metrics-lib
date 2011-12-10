/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;

/* Read GetTor stats from one or more local directories. */
public interface GetTorStatsReader {

  /* Add a local directory to read GetTor stats files from. */
  public void addDirectory(File directory);

  /* Read the previously configured GetTor stats files and make them
   * available via the returned blocking iterator.  Whenever the reader
   * runs out of descriptors and expects to provide more shortly after, it
   * blocks the caller.  This method can only be run once. */
  public Iterator<DescriptorFile> readDescriptors();
}

