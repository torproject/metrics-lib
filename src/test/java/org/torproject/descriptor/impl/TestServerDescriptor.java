/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

public class TestServerDescriptor extends ServerDescriptorImpl {

  protected TestServerDescriptor(byte[] rawDescriptorBytes,
      int[] offsetAndLength, boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, offsetAndLength, failUnrecognizedDescriptorLines);
  }

}



