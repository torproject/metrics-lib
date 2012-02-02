/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import org.torproject.descriptor.impl.DescriptorDownloaderImpl;
import org.torproject.descriptor.impl.DescriptorReaderImpl;

/* Create descriptor source instances. */
public class DescriptorSourceFactory {

  /* Create a descriptor reader. */
  public static DescriptorReader createDescriptorReader() {
    return new DescriptorReaderImpl();
  }

  /* Create a descriptor downloader. */
  public static DescriptorDownloader createDescriptorDownloader() {
    return new DescriptorDownloaderImpl();
  }
}

