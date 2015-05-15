/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParseException;
import java.util.List;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;

public class DescriptorParserImpl implements DescriptorParser {

  private boolean failUnrecognizedDescriptorLines;

  public void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines) {
    this.failUnrecognizedDescriptorLines =
        failUnrecognizedDescriptorLines;
  }

  public List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      String fileName) throws DescriptorParseException {
    return DescriptorImpl.parseDescriptors(rawDescriptorBytes, fileName,
        this.failUnrecognizedDescriptorLines);
  }
}
