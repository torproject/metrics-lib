/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import org.torproject.descriptor.impl.RelayDescriptorDownloaderImpl;
import org.torproject.descriptor.impl.RelayOrBridgeDescriptorReaderImpl;

/* Create descriptor source instances. */
public class DescriptorSourceFactory {

  /* Create a relay descriptor reader. */
  public static RelayDescriptorReader createRelayDescriptorReader() {
    return new RelayOrBridgeDescriptorReaderImpl();
  }

  /* Create a relay descriptor downloader. */
  public static RelayDescriptorDownloader
      createRelayDescriptorDownloader() {
    return new RelayDescriptorDownloaderImpl();
  }

  /* Create a bridge descriptor reader. */
  public static BridgeDescriptorReader createBridgeDescriptorReader() {
    return new RelayOrBridgeDescriptorReaderImpl();
  }

  /* Create a bridge pool assignment reader. */
  public static BridgePoolAssignmentReader
      createBridgePoolAssignmentReader() {
    return new RelayOrBridgeDescriptorReaderImpl();
  }
}

