/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.core.JsonParseException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.SortedMap;

public class IndexNodeTest {

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test
  public void testSimpleIndexRead() throws Exception {
    URL indexUrl = getClass().getClassLoader().getResource("index1.json");
    IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
    verifyIndex1(index);
  }

  /* toString is only used for debugging. Simply ensure that paths,
   * file names, and urls are readable. */
  @Test
  public void testToString() throws Exception {
    URL indexUrl = getClass().getClassLoader().getResource("index1.json");
    IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
    assertTrue(index.toString().contains("archive"));
    assertTrue(index.toString().contains("file-one.tar.xz"));
    assertTrue(index.toString().contains("file-two.tar.xz"));
    assertTrue(index.toString().contains("https://some.collector.url"));
  }

  private void verifyIndex1(IndexNode index) {
    assertEquals("https://some.collector.url", index.path);
    assertEquals("2016-01-01 00:01", index.created);
    assertEquals("archive", index.directories.first().path);
    assertEquals("path-one",
        index.directories.first().directories.first().path);
    assertEquals("file-one.tar.xz",
        index.directories.first().directories.first().files.first().path);
    assertEquals(624_156L,
        index.directories.first().directories.first().files.first().size);
    assertEquals("file-two.tar.xz",
        index.directories.first().directories.first().files.last().path);
  }

  @Test
  public void testCompressedIndexRead() throws Exception {
    for (String fileName : new String[] {"index1.json.xz", "index1.json.bz2",
        "index1.json.gz"}) {
      URL indexUrl = getClass().getClassLoader().getResource(fileName);
      IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
      verifyIndex1(index);
    }
  }

  @Test
  public void testIndexWrite() throws Exception {
    for (String fileName : new String[] {
        "test.json", "test.json.bz2", "test.json.gz", "test.json.xz"}) {
      URL indexUrl = getClass().getClassLoader().getResource(fileName);
      IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
      Path writtenIndex = tmpf.newFile("new" + fileName).toPath();
      IndexNode.writeIndex(writtenIndex, index);
      assertTrue("Verifying " + writtenIndex, Files.size(writtenIndex) > 20);
      compareContents(Paths.get(indexUrl.toURI()), writtenIndex);
    }
  }

  private void compareContents(Path oldPath, Path newPath) throws IOException {
    String oldJson = new String(Files.readAllBytes(oldPath));
    String newJson = new String(Files.readAllBytes(newPath));
    assertEquals("Comparing to " + oldPath, oldJson, newJson);
  }

  @Test
  public void testRetrieveFiles() throws Exception {
    URL indexUrl = getClass().getClassLoader().getResource("index2.json");
    IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
    assertTrue(index.retrieveFilesIn(new String[]{"b2"}).isEmpty());
    assertTrue(index.retrieveFilesIn(new String[]{"a1"}).isEmpty());
    SortedMap<String, FileNode> oneFile
        = index.retrieveFilesIn("a1/p2");
    assertFalse(oneFile.isEmpty());
    assertEquals(1330787700_000L,
        oneFile.get("a1/p2/file3").lastModifiedMillis());
    SortedMap<String, FileNode> twoFiles
        = index.retrieveFilesIn("y", "a1/x", "a1/p1");
    assertEquals(2, twoFiles.size());
    assertEquals(1328192040_000L,
        twoFiles.get("a1/p1/file2").lastModifiedMillis());
    SortedMap<String, FileNode> someFile
        = index.retrieveFilesIn("a1");
    assertTrue(someFile.isEmpty());
  }

  @Test(expected = IllegalArgumentException.class)
  public void testUnknownCompression() throws Exception {
    URL indexUrl = getClass()
        .getClassLoader().getResource("unknown.compression");
    IndexNode.fetchIndex(indexUrl.toString());
  }

  @Test(expected = JsonParseException.class)
  public void testWrongJson() throws Exception {
    URL indexUrl = getClass().getClassLoader().getResource("index1.json.gz");
    IndexNode.fetchIndex(indexUrl.openStream());
  }

  @Test
  public void testRetrieveEmpty() throws Exception {
    URL indexUrl = getClass().getClassLoader().getResource("index1.json");
    IndexNode index = IndexNode.fetchIndex(indexUrl.toString());
    Map<String, FileNode> map = index.retrieveFilesIn();
    assertTrue("map was " + map, map.isEmpty());
    map = index.retrieveFilesIn();
    assertTrue("map was " + map, map.isEmpty());
    map = index.retrieveFilesIn("/", null, "");
    assertTrue("map was " + map, map.isEmpty());
    indexUrl = getClass().getClassLoader().getResource("index3.json");
    index = IndexNode.fetchIndex(indexUrl.toString());
    map = index.retrieveFilesIn("a1/p1");
    assertTrue("map was " + map, map.isEmpty());
    map = index.retrieveFilesIn("a1/p3");
    assertTrue("map was " + map, map.isEmpty());
  }
}

