/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.util.List;

/**
 * Contains a log file.
 *
 * <p>Unlike other descriptors, logs can get very large and are typically stored
 * on disk in compressed form. However, all access to log contents through this
 * interface and its subinterfaces is made available in uncompressed form.</p>
 *
 * @since 2.2.0
 */
public interface LogDescriptor extends Descriptor {

  /**
   * Returns the decompressed raw descriptor bytes of the log.
   *
   * @since 2.2.0
   */
  @Override
  public byte[] getRawDescriptorBytes();

  /**
   * Returns annotations found in the log file, which may be an empty List if a
   * log format does not support adding annotations.
   *
   * @since 2.2.0
   */
  @Override
  public List<String> getAnnotations();

  /**
   * Returns unrecognized lines encountered while parsing the log, which may be
   * an empty list or a fixed-size list with only a few entries, depending on
   * the log type.
   *
   * @since 2.2.0
   */
  @Override
  public List<String> getUnrecognizedLines();

}

