/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

/**
 * @deprecated Replaced by
 *     org.torproject.descriptor.DescriptorParseException
 */
@Deprecated public class DescriptorParseException extends Exception {

  private static final long serialVersionUID = 100L;

  protected DescriptorParseException(String message) {
    super(message);
  }

  protected DescriptorParseException(String message, Exception ex) {
    super(message, ex);
  }

}

