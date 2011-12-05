/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Map;
import java.util.Set;

/* Read bridge descriptors from one or more local directories. */
public interface BridgeDescriptorReader extends DescriptorSource {

  /* Add a local directory to read bridge descriptors from. */
  public void addDirectory(File directory);

  /* Exclude the given file from the results. */
  public void setExcludeFile(File fileToExclude);

  /* Exclude the given files from the results. */
  public void setExcludeFiles(Set<File> filesToExclude);

  /* Define a limit in bytes up to which files are kept in memory, before
   * switching to storing file references and reading and parsing
   * descriptors on demand.  Setting this value to 0 disables caching and
   * leads to all descriptors being read and parsed on demand.  Default is
   * 50 MiB (50 * 1024 * 1024). */
  public void setInitialCacheLimit(long cacheLimitBytes);
}

