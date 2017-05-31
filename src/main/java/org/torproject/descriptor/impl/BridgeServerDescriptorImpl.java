/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.BridgeServerDescriptor;
import org.torproject.descriptor.DescriptorParseException;

public class BridgeServerDescriptorImpl extends ServerDescriptorImpl
    implements BridgeServerDescriptor {

  protected BridgeServerDescriptorImpl(byte[] rawDescriptorBytes,
      int[] offsetAndLength, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, offsetAndLength, failUnrecognizedDescriptorLines);
  }
}

