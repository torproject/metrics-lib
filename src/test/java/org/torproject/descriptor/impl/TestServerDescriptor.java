/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import java.io.File;

public class TestServerDescriptor extends ServerDescriptorImpl {

  protected TestServerDescriptor(byte[] rawDescriptorBytes,
      int[] offsetAndLength, File descriptorFile,
      boolean failUnrecognizedDescriptorLines)
      throws DescriptorParseException {
    super(rawDescriptorBytes, offsetAndLength, descriptorFile,
        failUnrecognizedDescriptorLines);
  }

}



