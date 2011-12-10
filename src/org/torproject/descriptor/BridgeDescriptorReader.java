/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/* Read bridge descriptors from one or more local directories. */
public interface BridgeDescriptorReader {

  /* Add a local directory to read bridge descriptors from. */
  public void addDirectory(File directory);

  /* Exclude the given file from the results. */
  public void setExcludeFile(File fileToExclude);

  /* Exclude the given files from the results. */
  public void setExcludeFiles(Set<File> filesToExclude);

  /* Read the previously configured bridge descriptors and make them
   * available via the returned blocking iterator.  Whenever the reader
   * runs out of descriptors and expects to provide more shortly after, it
   * blocks the caller.  This method can only be run once. */
  public Iterator<DescriptorFile> readDescriptors();
}

