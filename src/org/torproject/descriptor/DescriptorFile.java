/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.List;

/* Store meta-data about a descriptor file and a list of the contained
 * descriptors. */
public interface DescriptorFile {

  /* Return the directory where this descriptor file was contained. */
  public File getDirectory();

  /* Return the descriptor file itself. */
  public File getFile();

  /* Return the time in millis when the descriptor file on disk was last
   * modified. */
  public long getLastModified();

  /* Return the descriptors contained in the descriptor file. */
  public List<Descriptor> getDescriptors();
}

