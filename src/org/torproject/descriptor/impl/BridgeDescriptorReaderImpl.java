/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.File;
import java.util.Map;
import java.util.Set;
import org.torproject.descriptor.BridgeDescriptorReader;
import org.torproject.descriptor.DescriptorStore;

public class BridgeDescriptorReaderImpl implements BridgeDescriptorReader {

  public void addDirectory(File directory) {
    /* TODO Implement me. */
  }

  public void setExcludeFile(File fileToExclude) {
    /* TODO Implement me. */
  }

  public void setExcludeFiles(Set<File> filesToExclude) {
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

