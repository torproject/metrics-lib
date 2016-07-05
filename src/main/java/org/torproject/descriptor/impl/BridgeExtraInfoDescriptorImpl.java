/* Copyright 2015--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExtraInfoDescriptor;

import java.util.ArrayList;
import java.util.List;

public class BridgeExtraInfoDescriptorImpl
    extends ExtraInfoDescriptorImpl implements BridgeExtraInfoDescriptor {

  protected static List<ExtraInfoDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ExtraInfoDescriptor> parsedDescriptors = new ArrayList<>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "extra-info ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      ExtraInfoDescriptor parsedDescriptor =
          new BridgeExtraInfoDescriptorImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected BridgeExtraInfoDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines);
  }
}

