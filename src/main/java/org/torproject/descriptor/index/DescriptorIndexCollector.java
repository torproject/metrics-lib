/* Copyright 2015--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import org.torproject.descriptor.DescriptorCollector;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.Map;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * Download files from a CollecTor instance based on the remote
 * instance's index.json.
 *
 * @since 1.4.0
 */
public class DescriptorIndexCollector implements DescriptorCollector {

  private static Logger log = LoggerFactory
      .getLogger(DescriptorIndexCollector.class);

  /**
   * If <code>collecTorIndexUrlString</code> contains just the
   * base url, e.g. https://some.host.org, the path
   * <code>/index/index.json</code> will be appended.
   * If a path is given (even just a final slash, e.g. https://some.host.org/),
   * the <code>collecTorIndexUrlString</code> will be used as is.
   */
  @Override
  public void collectDescriptors(String collecTorIndexUrlString,
      String[] remoteDirectories, long minLastModified,
      File localDirectory, boolean deleteExtraneousLocalFiles) {
    log.info("Starting descriptor collection.");
    if (minLastModified < 0) {
      throw new IllegalArgumentException("A negative minimum "
          + "last-modified time is not permitted.");
    }
    if (null == collecTorIndexUrlString || null == remoteDirectories
        || null == localDirectory) {
      throw new IllegalArgumentException("Null values are not permitted for "
          + "CollecTor base URL, remote directories, or local directory.");
    }
    if (localDirectory.isFile()) {
      throw new IllegalArgumentException("A non-directory file exists at {} "
          + "which is supposed to be the local directory for storing remotely "
          + "fetched files.  Move this file away or delete it.  Aborting "
          + "descriptor collection.");
    }
    log.info("Indexing local directory {}.", localDirectory.getAbsolutePath());
    SortedMap<String, Long> localFiles = statLocalDirectory(localDirectory);
    SortedMap<String, FileNode> remoteFiles = null;
    IndexNode index = null;
    String indexUrlString = "";
    try {
      URL indexUrl = new URL(collecTorIndexUrlString);
      indexUrlString = indexUrl.toString();
      if (indexUrl.getPath().isEmpty()) {
        indexUrlString += "/index/index.json";
      }
      log.info("Fetching remote index file {}.", indexUrlString);
      index = IndexNode.fetchIndex(indexUrlString);
      remoteFiles = index.retrieveFilesIn(remoteDirectories);
    } catch (Exception ex) {
      log.warn("Cannot fetch index file {} and hence cannot determine which "
          + "remote files to fetch.  Aborting descriptor collection.",
          indexUrlString, ex);
      return;
    }
    log.info("Fetching remote files from {}.", index.path);
    if (!this.fetchRemoteFiles(index.path, remoteFiles, minLastModified,
        localDirectory, localFiles)) {
      return;
    }
    if (deleteExtraneousLocalFiles) {
      log.info("Deleting extraneous files from local directory {}.",
          localDirectory);
      deleteExtraneousLocalFiles(remoteFiles, localDirectory, localFiles);
    }
    log.info("Finished descriptor collection.");
  }

  boolean fetchRemoteFiles(String baseUrl, SortedMap<String, FileNode> remotes,
      long minLastModified, File localDir, SortedMap<String, Long> locals) {
    for (Map.Entry<String, FileNode> entry : remotes.entrySet()) {
      String filepathname = entry.getKey();
      String filename = entry.getValue().path;
      File filepath = new File(localDir,
          filepathname.replace(filename, ""));
      long lastModifiedMillis = entry.getValue().lastModifiedMillis();
      if (lastModifiedMillis < minLastModified
          || (locals.containsKey(filepathname)
              && locals.get(filepathname) >= lastModifiedMillis)) {
        continue;
      }
      if (!filepath.exists() && !filepath.mkdirs()) {
        log.warn("Cannot create local directory {} to store remote file {}.  "
            + "Aborting descriptor collection.", filepath, filename);
        return false;
      }
      File destinationFile = new File(filepath, filename);
      File tempDestinationFile = new File(filepath, "." + filename);
      log.debug("Fetching remote file {} with expected size of {} bytes from "
          + "{}, storing locally to temporary file {}, then renaming to {}.",
          filepathname, entry.getValue().size, baseUrl,
          tempDestinationFile.getAbsolutePath(),
          destinationFile.getAbsolutePath());
      try (InputStream is = new URL(baseUrl + "/" + filepathname)
          .openStream()) {
        Files.copy(is, tempDestinationFile.toPath());
        if (tempDestinationFile.length() == entry.getValue().size) {
          tempDestinationFile.renameTo(destinationFile);
          destinationFile.setLastModified(lastModifiedMillis);
        } else {
          log.warn("Fetched remote file {} from {} has a size of {} bytes "
              + "which is different from the expected {} bytes.  Not storing "
              + "this file.",
              filename, baseUrl, tempDestinationFile.length(),
              entry.getValue().size);
        }
      } catch (IOException e) {
        log.warn("Cannot fetch remote file {} from {}.  Skipping that file.",
            filename, baseUrl, e);
      }
    }
    return true;
  }

  static void deleteExtraneousLocalFiles(
      SortedMap<String, FileNode> remoteFiles,
      File localDir, SortedMap<String, Long> locals) {
    for (String localPath : locals.keySet()) {
      if (!remoteFiles.containsKey(localPath)) {
        File extraneousLocalFile = new File(localDir, localPath);
        log.debug("Deleting extraneous local file {}.",
            extraneousLocalFile.getAbsolutePath());
        extraneousLocalFile.delete();
      }
    }
  }

  static SortedMap<String, Long> statLocalDirectory(
      final File localDir) {
    final SortedMap<String, Long> locals = new TreeMap<>();
    if (!localDir.exists()) {
      return locals;
    }
    try {
      Files.walkFileTree(localDir.toPath(),
          new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path path, BasicFileAttributes bfa)
                throws IOException {
              locals.put(path.toFile().getAbsolutePath()
                  .replace(localDir.getAbsolutePath() + "/", ""),
                      path.toFile().lastModified());
              return FileVisitResult.CONTINUE;
            }
        });
    } catch (IOException ioe) {
      log.warn("Cannot index local directory {} to skip any remote files that "
          + "already exist locally.  Continuing with an either empty or "
          + "incomplete index of local files.", ioe);
    }
    return locals;
  }
}

