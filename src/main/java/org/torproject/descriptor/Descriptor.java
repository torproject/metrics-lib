/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;

/**
 * Superinterface for any descriptor with access to generic information
 * about the descriptor.
 *
 * @since 1.0.0
 */
public interface Descriptor {

  /**
   * Return the raw descriptor bytes.
   *
   * @since 1.0.0
   */
  public byte[] getRawDescriptorBytes();

  /**
   * Return the (possibly empty) list of annotations in the format
   * {@code "@key( value)*"}.
   *
   * @since 1.0.0
   */
  public List<String> getAnnotations();

  /**
   * Return any unrecognized lines when parsing this descriptor, or an
   * empty list if there were no unrecognized lines.
   *
   * @since 1.0.0
   */
  public List<String> getUnrecognizedLines();
}

