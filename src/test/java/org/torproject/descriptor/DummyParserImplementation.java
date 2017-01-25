/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import org.torproject.descriptor.impl.DescriptorParserImpl;

class DummyParserImplementation extends DescriptorParserImpl {

  static int count;

  public DummyParserImplementation() {
    count++;
  }
}
