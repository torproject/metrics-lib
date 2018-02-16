/* Copyright 2017--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.io.InputStream;
import java.util.List;

/**
 * Contains a log file.
 *
 * <p>Unlike other descriptors, logs can get very large and are typically stored
 * on disk in compressed form. Access to log contents through this
 * interface and its subinterfaces is made available in compressed and
 * decompressed form:
 * <ul>
 * <li>The raw descriptor bytes are compressed, because logs contain
 * often redundant information that can achieve high compression rates.
 * For example, a 500kB compressed log file might be deflated to 3GB.</li>
 * <li>The uncompressed log contents can be accessed as a stream of bytes.</li>
 * <li>A list of log lines (decompressed) can be retrieved.</li>
 * </ul>
 * </p>
 *
 * @since 2.2.0
 */
public interface LogDescriptor extends Descriptor {

  /**
   * Returns the raw compressed descriptor bytes of the log.
   *
   * <p>For access to the log's decompressed bytes of
   * use method {@code decompressedByteStream}.</p>
   *
   * @since 2.2.0
   */
  @Override
  public byte[] getRawDescriptorBytes();

  /**
   * Returns the decompressed raw descriptor bytes of the log as stream.
   *
   * @since 2.2.0
   */
  public InputStream decompressedByteStream() throws DescriptorParseException;

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

  /**
   * Returns a list of all parseable log lines.
   * <p>Might require a lot of memory depending on log size.</p>
   */
  public List<? extends Line> logLines() throws DescriptorParseException;

  public interface Line {

    /** Returns a log line string. */
    public String toLogString();

  }
}

