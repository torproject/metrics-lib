/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import org.torproject.descriptor.impl.DescriptorDownloaderImpl;

class DummyDownloaderImplementation extends DescriptorDownloaderImpl {

  static int count;

  public DummyDownloaderImplementation() {
    count++;
  }
}
