/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

import org.torproject.descriptor.impl.DescriptorParseException;

/* Parse descriptors that are already in memory instead of using the
 * descriptor reader or downloader. */
public interface DescriptorParser {

  /* Fail descriptor parsing when encountering an unrecognized line.  This
   * is not set by default, because the Tor specifications allow for new
   * lines to be added that shall be ignored by older Tor versions.  But
   * some applications may want to handle unrecognized descriptor lines
   * explicitly. */
  public void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines);

  /* Parse descriptors in the given byte array, possibly parsing the
   * publication time from the file name (depending on the descriptor
   * type). */
  public List<Descriptor> parseDescriptors(byte[] rawDescriptorBytes,
      String fileName) throws DescriptorParseException;
}
