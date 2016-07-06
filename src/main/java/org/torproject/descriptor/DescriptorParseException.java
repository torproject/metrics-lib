/* Copyright 2014--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

/**
 * Thrown if raw descriptor contents cannot be parsed to one or more
 * {@link Descriptor} instances, according to descriptor specifications.
 *
 * @since 1.0.0
 */
@SuppressWarnings("deprecation")
public class DescriptorParseException
    extends org.torproject.descriptor.impl.DescriptorParseException {

  private static final long serialVersionUID = 100L;

  public DescriptorParseException(String message) {
    super(message);
  }

  public DescriptorParseException(String message, Exception ex) {
    super(message, ex);
  }

}

