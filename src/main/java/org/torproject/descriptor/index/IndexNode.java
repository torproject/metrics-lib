/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import org.torproject.descriptor.internal.FileType;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.Reader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

/**
 * An index node is the top-level node in the JSON structure.
 * It provides some utility methods for reading
 * and searching (in a limited way) it's sub-structure.
 *
 * @since 1.4.0
 */
public class IndexNode {

  private static Logger log = LoggerFactory.getLogger(IndexNode.class);

  /** An empty node, which is not added to JSON output. */
  public static final IndexNode emptyNode = new IndexNode("", "",
      new TreeSet<FileNode>(), new TreeSet<DirectoryNode>());

  /** The created date-time is exposed in JSON as 'index_created' field. */
  @Expose
  @SerializedName("index_created")
  public final String created;

  /** The software's build revision JSON as 'build_revision' field. */
  @Expose
  @SerializedName("build_revision")
  public final String revision;

  /** Path (i.e. base url) is exposed in JSON. */
  @Expose
  public final String path;

  /** The directory list is exposed in JSON. Sorted according to path. */
  @Expose
  public final SortedSet<DirectoryNode> directories;

  /** The file list is exposed in JSON. Sorted according to path. */
  @Expose
  public final SortedSet<FileNode> files;

  /* Added to satisfy Gson. */
  private IndexNode() {
    this.created = null;
    this.revision = null;
    this.path = null;
    this.files = null;
    this.directories = null;
  }

  /** For backwards compatibility and testing. */
  public IndexNode(String created, String path,
            SortedSet<FileNode> files,
            SortedSet<DirectoryNode> directories) {
    this(created, null, path, files, directories);
  }

  /** An index node is the top-level node in the JSON structure. */
  public IndexNode(String created, String revision, String path,
            SortedSet<FileNode> files,
            SortedSet<DirectoryNode> directories) {
    this.created = created;
    this.revision = revision;
    this.path = path;
    this.files = files;
    this.directories = directories;
  }

  /**
   * Reads JSON from given URL String.
   * Returns an empty IndexNode in case of an error.
   */
  public static IndexNode fetchIndex(String urlString) throws Exception {
    String ending
        = urlString.substring(urlString.lastIndexOf(".") + 1).toUpperCase();
    try (InputStream is = FileType.valueOf(ending)
        .inputStream(new URL(urlString).openStream())) {
      return fetchIndex(is);
    }
  }

  /**
   * Reads JSON from given InputStream.
   * Returns an empty IndexNode in case of an error.
   */
  public static IndexNode fetchIndex(InputStream is) throws IOException {
    Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation()
        .create();
    try (Reader reader = new InputStreamReader(is)) {
      return gson.fromJson(reader, IndexNode.class);
    }
  }

  /** Return a map of file paths for the given directories. */
  public SortedMap<String, FileNode> retrieveFilesIn(String ... remoteDirs) {
    SortedMap<String, FileNode> map = new TreeMap<>();
    for (String remote : remoteDirs) {
      if (null == remote || remote.isEmpty()) {
        continue;
      }
      String[] dirs = remote.replaceAll("/", " ").trim().split(" ");
      DirectoryNode currentDir = findPathIn(dirs[0], this.directories);
      if (null == currentDir) {
        continue;
      }
      String currentPath = dirs[0] + "/";
      for (int k = 1; k < dirs.length; k++) {
        DirectoryNode dn = findPathIn(dirs[k], currentDir.directories);
        if (null == dn) {
          break;
        } else {
          currentPath += dirs[k] + "/";
          currentDir = dn;
        }
      }
      if (null == currentDir.files) {
        continue;
      }
      for (FileNode file : currentDir.files) {
        if (file.lastModifiedMillis() > 0) { // only add valid files
          map.put(currentPath + file.path, file);
        }
      }
    }
    return map;
  }

  /** Returns the directory nodes with the given path, but no file nodes. */
  public static DirectoryNode findPathIn(String path,
      SortedSet<DirectoryNode> dirs) {
    if (null != dirs) {
      for (DirectoryNode dn : dirs) {
        if (dn.path.equals(path)) {
          return dn;
        }
      }
    }
    return null;
  }

  /** Write JSON representation of the given index node to the given path. */
  public static void writeIndex(Path outPath, IndexNode indexNode)
      throws Exception {
    String ending = outPath.toString()
        .substring(outPath.toString().lastIndexOf(".") + 1).toUpperCase();
    try (OutputStream os = FileType.valueOf(ending)
         .outputStream(Files.newOutputStream(outPath))) {
      os.write(makeJsonString(indexNode).getBytes());
    }
  }

  /** Write JSON representation of the given index node to a string. */
  public static String makeJsonString(IndexNode indexNode) {
    Gson gson = new GsonBuilder().excludeFieldsWithoutExposeAnnotation()
        .create();
    return gson.toJson(indexNode);
  }

  /** For debugging purposes. */
  @Override
  public String toString() {
    return "index: " + path + ", created " + created
        + ",\nfns: " + files + ",\ndirs: " + directories;
  }
}

