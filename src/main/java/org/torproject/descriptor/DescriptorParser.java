/* Copyright 2012--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.io.File;

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
   * Parse descriptors in the given byte array and return the parsed/unparseable
   * descriptors.
   *
   * @param rawDescriptorBytes Raw descriptor bytes containing one or more
   *     descriptors
   * @param descriptorFile Optional descriptor file reference included in
   *     parsed/unparseable descriptors
   * @param fileName Descriptor file name used for parsing the descriptor
   *     publication time of some descriptor types
   *
   * @return Parsed/unparseable descriptors
   *
   * @since 1.9.0
   */
  public Iterable<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      File descriptorFile, String fileName);
}
