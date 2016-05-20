/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.io.File;
import java.util.List;

/**
 * Container for descriptors read from a file.
 *
 * <p>When the {@link DescriptorReader} reads descriptors from local files
 * it provides an iterator over these containers which in turn contain
 * references to classes implementing the {@link Descriptor} interface.
 * This container also stores potentially useful meta-data about the
 * descriptor file.</p>
 *
 * @since 1.0.0
 */
public interface DescriptorFile {

  /**
   * Return the directory where this descriptor file was contained, or
   * null if the file was contained in a tarball.
   *
   * @since 1.0.0
   */
  public File getDirectory();

  /**
   * Return the tarball where this descriptor file was contained, or null
   * if the file was not contained in a tarball.
   *
   * @since 1.0.0
   */
  public File getTarball();

  /**
   * Return the descriptor file itself, or null if the descriptor file
   * was contained in a tarball.
   *
   * @since 1.0.0
   */
  public File getFile();

  /**
   * Return the descriptor file name, which is either the absolute path
   * of the file on disk, or the tar file entry name.
   *
   * @since 1.0.0
   */
  public String getFileName();

  /**
   * Return the time in milliseconds since the epoch when the descriptor
   * file on disk was last modified.
   *
   * @since 1.0.0
   */
  public long getLastModified();

  /**
   * Return the descriptors contained in the descriptor file.
   *
   * @since 1.0.0
   */
  public List<Descriptor> getDescriptors();

  /**
   * Return the first exception that was thrown when reading this file or
   * parsing its content, or null if no exception was thrown.
   *
   * @since 1.0.0
   */
  public Exception getException();
}

