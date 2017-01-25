/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import org.torproject.descriptor.index.DescriptorIndexCollector;

class DummyCollectorImplementation extends DescriptorIndexCollector {

  static int count;

  public DummyCollectorImplementation() {
    count++;
  }
}
