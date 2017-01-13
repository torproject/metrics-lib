/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;

/**
 * Descriptor source that parses descriptors from raw descriptor contents.
 *
 * <p>Unlike most of the other descriptor sources this descriptor source
 * does not operate in a batch-processing mode.  It takes the raw
 * descriptor contents of one or more descriptors, parses them, and
 * returns a list of descriptors.</p>
 *
 * <p>This descriptor source is internally used by other descriptor
 * sources but can also be used directly by applications that obtain
 * raw descriptor contents via other means than one of the existing
 * descriptor sources.</p>
 *
 * @since 1.0.0
 */
public interface DescriptorParser {

  /**
   * Fail descriptor parsing when encountering an unrecognized line.
   *
   * <p>This option is not set by default, because the Tor specifications
   * allow for new lines to be added that shall be ignored by older Tor
   * versions.  But some applications may want to handle unrecognized
   * descriptor lines explicitly.</p>
   *
   * @since 1.0.0
   */
  public void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines);

  /**
   * Parse descriptors in the given byte array, possibly parsing the
   * publication time from the file name, depending on the descriptor
   * type.
   *
   * @since 1.0.0
   */
  public List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      String fileName) throws DescriptorParseException;
}
