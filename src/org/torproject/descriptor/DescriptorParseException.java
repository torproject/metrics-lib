/* Copyright 2014 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

@SuppressWarnings("deprecation")
public class DescriptorParseException
    extends org.torproject.descriptor.impl.DescriptorParseException {
  private static final long serialVersionUID = 100L;
  public DescriptorParseException(String message) {
    super(message);
  }
}

