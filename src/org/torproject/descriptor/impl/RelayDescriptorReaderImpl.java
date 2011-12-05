/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.File;
import java.util.Map;
import java.util.Set;
import org.torproject.descriptor.DescriptorStore;
import org.torproject.descriptor.RelayDescriptorReader;

public class RelayDescriptorReaderImpl implements RelayDescriptorReader {

  public void addDirectory(File directory) {
    /* TODO Implement me. */
  }

  public void setExcludeFile(File fileToExclude) {
    /* TODO Implement me. */
  }

  public void setExcludeFiles(Set<File> filesToExclude) {
    /* TODO Implement me. */
  }

  public void setExcludeFile(File fileToExclude, long lastModifiedMillis) {
    /* TODO Implement me. */
  }

  public void setExcludeFiles(Map<File, Long> filesToExclude) {
    /* TODO Implement me. */
  }

  public void setInitialCacheLimit(long cacheLimitBytes) {
    /* TODO Implement me. */
  }

  public DescriptorStore initialize() {
    /* TODO Implement me. */
    return new DescriptorStoreImpl();
  }
}

