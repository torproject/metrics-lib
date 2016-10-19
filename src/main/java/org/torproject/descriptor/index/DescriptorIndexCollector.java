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
    if (minLastModified < 0) {
      throw new IllegalArgumentException("A negative minimum "
          + "last-modified time is not permitted.");
    }
    if (null == localDirectory || localDirectory.isFile()) {
      throw new IllegalArgumentException("Local directory already exists "
          + "and is not a directory.");
    }
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
      index = IndexNode.fetchIndex(indexUrlString);
      remoteFiles = index.retrieveFilesIn(remoteDirectories);
    } catch (Exception ex) {
      throw new RuntimeException("Cannot fetch index from '"
          + indexUrlString + "'.", ex);
    }
    this.fetchRemoteFiles(index.path, remoteFiles, minLastModified,
        localDirectory, localFiles);
    if (deleteExtraneousLocalFiles) {
      this.deleteExtraneousLocalFiles(remoteFiles, localDirectory, localFiles);
    }
  }

  void fetchRemoteFiles(String baseUrl, SortedMap<String, FileNode> remotes,
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
        throw new RuntimeException("Cannot create dir: " + filepath);
      }
      File destinationFile = new File(filepath, filename);
      File tempDestinationFile = new File(filepath, "." + filename);
      try (InputStream is = new URL(baseUrl + "/" + filepathname)
          .openStream()) {
        Files.copy(is, tempDestinationFile.toPath());
        if (tempDestinationFile.length() == entry.getValue().size) {
          tempDestinationFile.renameTo(destinationFile);
          destinationFile.setLastModified(lastModifiedMillis);
        } else {
          log.warn("File sizes don't match. Expected {},  but received {}.",
              entry.getValue().size, tempDestinationFile.length());
        }
      } catch (IOException e) {
        log.error("Cannot fetch remote file: {}", filename, e);
      }
    }
  }

  static void deleteExtraneousLocalFiles(
      SortedMap<String, FileNode> remoteFiles,
      File localDir, SortedMap<String, Long> locals) {
    for (String localPath : locals.keySet()) {
      if (!remoteFiles.containsKey(localPath)) {
        new File(localDir, localPath).delete();
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
      log.error("Cannot stat local directory.", ioe);
    }
    return locals;
  }
}

