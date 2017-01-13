/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import java.io.File;
import java.util.Iterator;
import java.util.SortedMap;

/**
 * Descriptor source that reads descriptors from local files and provides
 * an iterator over parsed descriptors.
 *
 * <p>This descriptor source is likely the most widely used one, possibly
 * in combination with {@link DescriptorCollector} to synchronize
 * descriptors from the CollecTor service.</p>
 *
 * <p>Reading descriptors is done in a batch which starts after setting
 * any configuration options and initiating the read process.</p>
 *
 * <p>Code sample:</p>
 * <pre>{@code
 * DescriptorReader descriptorReader =
 *     DescriptorSourceFactory.createDescriptorReader();
 * // Read descriptors from local directory called in/.
 * descriptorReader.addDirectory(new File("in"));
 * Iterator<DescriptorFile> descriptorFiles =
 *     descriptorReader.readDescriptors();
 * while (descriptorFiles.hasNext()) {
 *   DescriptorFile descriptorFile = descriptorFiles.next();
 *   for (Descriptor descriptor : descriptorFile.getDescriptors()) {
 *     if ((descriptor instanceof RelayNetworkStatusConsensus)) {
 *       // Only process network status consensuses, ignore the rest.
 *       RelayNetworkStatusConsensus consensus =
 *           (RelayNetworkStatusConsensus) descriptor;
 *       processConsensus(consensus);
 *     }
 *   }
 * }}</pre>
 *
 * @since 1.0.0
 */
public interface DescriptorReader {

  /**
   * Add a local directory to read descriptors from, which may contain
   * descriptor files or tarballs containing descriptor files.
   *
   * @since 1.0.0
   */
  public void addDirectory(File directory);

  /**
   * Add a tarball to read descriptors from, which may be uncompressed,
   * bz2-compressed, or xz-compressed.
   *
   * @since 1.0.0
   */
  public void addTarball(File tarball);

  /**
   * Exclude files that are listed in the given history file and that
   * haven't changed since they have last been read.
   *
   * <p>Add a new line for each descriptor that is read in this execution
   * and remove lines for files that don't exist anymore.</p>
   *
   * <p>Lines in the history file contain the last modified time in
   * milliseconds since the epoch and the absolute path of a file.</p>
   *
   * @deprecated Replaced by {@link #setHistoryFile()} and
   *     {@link #saveHistoryFile()} which let the application explicitly tell us
   *     when it's done processing read descriptors.
   *
   * @since 1.0.0
   */
  public void setExcludeFiles(File historyFile);

  /**
   * Set a history file to load before reading descriptors and exclude
   * descriptor files that haven't changed since they have last been read.
   *
   * <p>Lines in the history file contain the last modified time in
   * milliseconds since the epoch and the absolute path of a file, separated by
   * a space.</p>
   *
   * @since 1.6.0
   */
  public void setHistoryFile(File historyFile);

  /**
   * Save a history file with file names and last modified timestamps of
   * descriptor files that exist in the input directory or directories and that
   * have either been parsed or excluded from parsing.
   *
   * <p>Lines in the history file contain the last modified time in
   * milliseconds since the epoch and the absolute path of a file, separated by
   * a space.</p>
   *
   * @since 1.6.0
   */
  public void saveHistoryFile(File historyFile);

  /**
   * Exclude files if they haven't changed since the corresponding last
   * modified timestamps.
   *
   * <p>Can be used instead of (or in addition to) a history file.</p>
   *
   * @since 1.0.0
   */
  public void setExcludedFiles(SortedMap<String, Long> excludedFiles);

  /**
   * Return files and last modified timestamps of files that exist in the
   * input directory or directories, but that have been excluded from
   * parsing, because they haven't changed since they were last read.
   *
   * <p>Can be used instead of (or in addition to) a history file when
   * combined with the set of parsed files.</p>
   *
   * @since 1.0.0
   */
  public SortedMap<String, Long> getExcludedFiles();

  /**
   * Return files and last modified timestamps of files that exist in the
   * input directory or directories and that have been parsed.
   *
   * <p>Can be used instead of (or in addition to) a history file when
   * combined with the set of excluded files.</p>
   *
   * @since 1.0.0
   */
  public SortedMap<String, Long> getParsedFiles();

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
  public void setFailUnrecognizedDescriptorLines();

  /**
   * Don't keep more than this number of parsed descriptor files in the
   * queue.
   *
   * <p>The default is 100, but if descriptor files contain hundreds or
   * even thousands of descriptors, that default may be too high.</p>
   *
   * @since 1.0.0
   */
  public void setMaxDescriptorFilesInQueue(int max);

  /**
   * Read the previously configured descriptors and make them available
   * via the returned blocking iterator.
   *
   * <p>Whenever the reader runs out of descriptors and expects to provide
   * more shortly after, it blocks the caller.  This method can only be
   * run once.</p>
   *
   * @since 1.0.0
   */
  public Iterator<DescriptorFile> readDescriptors();
}

