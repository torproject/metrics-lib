/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import org.torproject.descriptor.impl.DescriptorReaderImpl;

class DummyReaderImplementation extends DescriptorReaderImpl {

  static int count;

  public DummyReaderImplementation() {
    count++;
  }
}
