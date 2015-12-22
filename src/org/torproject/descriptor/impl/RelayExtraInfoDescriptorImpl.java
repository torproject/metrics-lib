/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.ExtraInfoDescriptor;
import org.torproject.descriptor.RelayExtraInfoDescriptor;

public class RelayExtraInfoDescriptorImpl
    extends ExtraInfoDescriptorImpl implements RelayExtraInfoDescriptor {

  protected static List<ExtraInfoDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ExtraInfoDescriptor> parsedDescriptors = new ArrayList<>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "extra-info ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      ExtraInfoDescriptor parsedDescriptor =
          new RelayExtraInfoDescriptorImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected RelayExtraInfoDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines);
  }
}

