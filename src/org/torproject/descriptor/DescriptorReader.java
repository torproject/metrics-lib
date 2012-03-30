/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;

/* Read descriptors from one or more local directories. */
public interface DescriptorReader {

  /* Add a local directory to read descriptor files or tarballs containing
   * descriptor files from. */
  public void addDirectory(File directory);

  /* Add an uncompressed or bz2-compressed tarball to read descriptors
   * from. */
  public void addTarball(File tarball);

  /* Exclude files that are contained in the given history file and that
   * haven't changed since they were last read.  Add reads from the
   * current run to the history file.  Remove files that don't exist
   * anymore from the history file.  Lines in the history file contain the
   * last modified timestamp and the absolute path of a file. */
  public void setExcludeFiles(File historyFile);

  /* Fail descriptor parsing when encountering an unrecognized line.  This
   * is not set by default, because the Tor specifications allow for new
   * lines to be added that shall be ignored by older Tor versions.  But
   * some applications may want to handle unrecognized descriptor lines
   * explicitly. */
  public void setFailUnrecognizedDescriptorLines();

  /* Read the previously configured descriptors and make them available
   * via the returned blocking iterator.  Whenever the reader runs out of
   * descriptors and expects to provide more shortly after, it blocks the
   * caller.  This method can only be run once. */
  public Iterator<DescriptorFile> readDescriptors();
}

