/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;

/* Read relay descriptors from one or more local directories. */
public interface RelayDescriptorReader {

  /* Add a local directory to read relay descriptors from. */
  public void addDirectory(File directory);

  /* Exclude files that are contained in the given history file and that
   * haven't changed since they were last read.  Add reads from the
   * current run to the history file.  Remove files that don't exist
   * anymore from the history file.  Lines in the history file contain the
   * last modified timestamp and the absolute path of a file. */
  public void setExcludeFiles(File historyFile);

  /* Read the previously configured relay descriptors and make them
   * available via the returned blocking iterator.  Whenever the reader
   * runs out of descriptors and expects to provide more shortly after, it
   * blocks the caller.  This method can only be run once. */
  public Iterator<DescriptorFile> readDescriptors();

}

