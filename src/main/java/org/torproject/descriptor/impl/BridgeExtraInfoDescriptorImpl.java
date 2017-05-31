/* Copyright 2015--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.DescriptorParseException;

public class BridgeExtraInfoDescriptorImpl
    extends ExtraInfoDescriptorImpl implements BridgeExtraInfoDescriptor {

  protected BridgeExtraInfoDescriptorImpl(byte[] descriptorBytes,
      int[] offsetAndLimit, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, offsetAndLimit, failUnrecognizedDescriptorLines);
  }
}

