/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParseException;
import org.torproject.descriptor.DescriptorParser;

import java.util.List;

public class DescriptorParserImpl implements DescriptorParser {

  private boolean failUnrecognizedDescriptorLines;

  @Override
  public void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines) {
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
  }

  @Override
  public List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      String fileName) throws DescriptorParseException {
    return DescriptorImpl.parseDescriptors(rawDescriptorBytes, fileName,
        this.failUnrecognizedDescriptorLines);
  }
}
