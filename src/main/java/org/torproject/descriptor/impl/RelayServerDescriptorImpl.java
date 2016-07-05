/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.ArrayList;
import java.util.List;

import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.RelayServerDescriptor;
import org.torproject.descriptor.ServerDescriptor;

public class RelayServerDescriptorImpl extends ServerDescriptorImpl
    implements RelayServerDescriptor {

  protected static List<ServerDescriptor> parseDescriptors(
      byte[] descriptorsBytes, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    List<ServerDescriptor> parsedDescriptors = new ArrayList<>();
    List<byte[]> splitDescriptorsBytes =
        DescriptorImpl.splitRawDescriptorBytes(descriptorsBytes,
        "router ");
    for (byte[] descriptorBytes : splitDescriptorsBytes) {
      ServerDescriptor parsedDescriptor =
          new RelayServerDescriptorImpl(descriptorBytes,
          failUnrecognizedDescriptorLines);
      parsedDescriptors.add(parsedDescriptor);
    }
    return parsedDescriptors;
  }

  protected RelayServerDescriptorImpl(byte[] descriptorBytes,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(descriptorBytes, failUnrecognizedDescriptorLines);
  }
}

