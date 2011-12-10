/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;
import org.torproject.descriptor.DescriptorFile;

/* Read Torperf data files from one or more local directories. */
public interface TorperfDataReader {

  /* Add a local directory to read Torperf data files from. */
  public void addDirectory(File directory);

  /* Read the previously configured Torperf data files and make them
   * available via the returned blocking iterator.  Whenever the reader
   * runs out of descriptors and expects to provide more shortly after, it
   * blocks the caller.  This method can only be run once. */
  public Iterator<DescriptorFile> readDescriptors();
}

