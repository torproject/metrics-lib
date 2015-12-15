/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;

import org.torproject.descriptor.BridgeExtraInfoDescriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExtraInfoDescriptor;

public class BridgeExtraInfoDescriptorImpl
    extends ExtraInfoDescriptorImpl implements BridgeExtraInfoDescriptor {

  protected static List<ExtraInfoDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ExtraInfoDescriptor> parsedDescriptors =
        new ArrayList<ExtraInfoDescriptor>();
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

