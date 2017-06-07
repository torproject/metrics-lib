/* Copyright 2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

public class TestDescriptor extends DescriptorImpl {

  protected TestDescriptor(byte[] rawDescriptorBytes, int[] offsetAndLength,
      boolean failUnrecognizedDescriptorLines, boolean blankLinesAllowed)
      throws DescriptorParseException {
    super(rawDescriptorBytes, offsetAndLength,
        failUnrecognizedDescriptorLines, blankLinesAllowed);
  }
}



