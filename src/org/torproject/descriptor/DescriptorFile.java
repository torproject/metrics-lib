/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.List;

/* Store meta-data about a descriptor file and a list of the contained
 * descriptors. */
public interface DescriptorFile {

  /* Return the directory where this descriptor file was contained, or
   * null if the file was contained in a tarball. */
  public File getDirectory();

  /* Return the tarball where this descriptor file was contained, or null
   * if the file was not contained in a tarball. */
  public File getTarball();

  /* Return the descriptor file itself, or null if the descriptor file was
   * contained in a tarball. */
  public File getFile();

  /* Return the descriptor file name, which is either the absolute path of
   * the file on disk, or the tar file entry name. */
  public String getFileName();

  /* Return the time in millis when the descriptor file on disk was last
   * modified. */
  public long getLastModified();

  /* Return the descriptors contained in the descriptor file. */
  public List<Descriptor> getDescriptors();

  /* Return the first exception that was thrown when reading this file or
   * parsing its content, or null if no exception was thrown. */
  public Exception getException();
}

