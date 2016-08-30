/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import org.torproject.descriptor.DescriptorCollector;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.TreeMap;
import java.util.TreeSet;

public class DescriptorIndexCollectorTest {

  @Rule
  public ExpectedException thrown = ExpectedException.none();

  @Rule
  public TemporaryFolder tmpf = new TemporaryFolder();

  @Test()
  public void testNormalCollecting() throws Exception {
    // create local file structure
    File localFolder = tmpf.newFolder();
    makeStructure(localFolder, "1");

    // create remote file structure
    File remoteDirectory = tmpf.newFolder();
    makeStructure(remoteDirectory, "2");

    File indexFile = newIndexFile("testindex.json",
        remoteDirectory.toURL().toString());

    // verify precondition for test.
    checkContains(true,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/x1", "a/b/y1", "a/b/c/w1", "a/b/c/z1", "a/b/c/u1");
    checkContains(false,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/y2","a/b/x2");

    DescriptorCollector dc = new DescriptorIndexCollector();
    dc.collectDescriptors(indexFile.toURL().toString(),
        new String[]{"a/b", "a"}, 1451606400_000L, localFolder, false);

    // verify that files in 'a/b' were fetched
    checkContains(true,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/x1", "a/b/y1", "a/b/y2","a/b/x2", "a/b/c/w1", "a/b/c/z1");

    // verify that files in 'a/b/c' were not fetched.
    checkContains(false,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/c/u2");
  }

  private void makeStructure(File folder, String suffix) throws IOException {
    File dir = makeDirs(folder.toString(), "a", "b");
    makeFiles(dir, "x" + suffix, "y" + suffix);
    File subdir = makeDirs(dir.toString(), "c");
    makeFiles(subdir, "u" + suffix, "w" + suffix, "z" + suffix);
    SortedMap<String, Long> local = DescriptorIndexCollector
        .statLocalDirectory(folder);
    assertEquals("found " + local, 5, local.size());
  }

  private File makeDirs(String first, String ... dirs) throws IOException {
    File dir = Files.createDirectories(Paths.get(first, dirs)).toFile();
    assertTrue(dir.isDirectory());
    return dir;
  }

  private void makeFiles(File dir, String ... files) throws IOException {
    for (String file : files) {
      assertTrue(new File(dir, file).createNewFile());
    }
  }

  private void checkContains(boolean should, String listing,
      String ... vals) {
    for (String part : vals) {
      if (should) {
        assertTrue("missing " + part + " in " + listing,
            listing.contains(part));
      } else {
        assertFalse("Shouldn't be: " + part + " in " + listing,
            listing.contains(part));
      }
    }
  }

  private File newIndexFile(String name, String remoteDirectory)
      throws Exception {
    SortedSet<FileNode> fm = new TreeSet<>();

    // 'u2' should be fetched when the path is included.
    fm.add(new FileNode("u2", 0L, "2100-01-01 01:02"));

    // 'w2' should not be fetched, b/c of wrong filesize
    fm.add(new FileNode("w2", 100L, "2100-01-01 01:01"));

    // 'z2' should not be fetched, b/c of being too old.
    fm.add(new FileNode("z2", 0L, "1900-01-01 01:02"));
    SortedSet<DirectoryNode> dm = new TreeSet<>();
    dm.add(new DirectoryNode("c", fm, null));
    fm = new TreeSet<>();

    // 'x2' and 'y2' should be fetched when their path is included.
    fm.add(new FileNode("x2", 0L, "2100-01-01 01:01"));
    fm.add(new FileNode("y2", 0L, "2100-01-01 01:02"));
    DirectoryNode dnb = new DirectoryNode("b", fm, dm);
    dm = new TreeSet<>();
    dm.add(dnb);
    DirectoryNode dna = new DirectoryNode("a", null, dm);
    dm = new TreeSet<>();
    dm.add(dna);
    IndexNode in = new IndexNode("2016-01-01 01:01",
        remoteDirectory, null, dm);
    File indexFile = tmpf.newFile(name);
    in.writeIndex(indexFile.toPath(), in);
    return indexFile;
  }

  @Test()
  public void testNormalCollectingWithDeletion() throws Exception {
    File localFolder = tmpf.newFolder();
    makeStructure(localFolder, "1");

    File remoteDirectory = tmpf.newFolder();
    makeStructure(remoteDirectory, "2");

    File indexFile = newIndexFile("testindexDelete.json",
        remoteDirectory.toURL().toString());

    // verify precondition for test.
    checkContains(true,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/x1", "a/b/y1", "a/b/c/w1", "a/b/c/z1", "a/b/c/u1");
    checkContains(false,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/y2","a/b/x2");

    new DescriptorIndexCollector()
        .collectDescriptors(indexFile.toURL().toString(),
            new String[]{"a/b", "a/b/c"}, 1451606400_000L, localFolder, true);

    // verify file addition.
    checkContains(true,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/y2", "a/b/x2", "a/b/c/u2");

    // verify that invalid files weren't fetched.
    checkContains(false,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/c/w2", "a/b/c/z2");

    // verify file deletion.
    checkContains(false,
        DescriptorIndexCollector.statLocalDirectory(localFolder).toString(),
        "a/b/x1", "a/b/y1", "a/b/c/w1", "a/b/c/z1", "a/b/c/u1");
  }

  @Test()
  public void testNormalStatLocalDirectory() throws IOException {
    // create local file structure
    File dir = tmpf.newFolder();
    File ab = makeDirs(dir.toString(), "a", "b");
    SortedMap<String, Long> res = DescriptorIndexCollector
        .statLocalDirectory(dir);
    assertTrue("found " + res, res.isEmpty());
    makeFiles(ab, "x");
    res = DescriptorIndexCollector.statLocalDirectory(dir);
    assertFalse("found " + res, res.isEmpty());
    assertEquals("found " + res, 1, res.size());
    assertNotNull("found " + res, res.get("a/b/x"));
    File subdir = makeDirs(ab.toString(), "c");
    makeFiles(subdir, "y");
    res = DescriptorIndexCollector.statLocalDirectory(dir);
    assertFalse("found " + res, res.isEmpty());
    assertEquals("found " + res, 2, res.size());
    assertNotNull("found " + res, res.get("a/b/x"));
    assertNotNull("found " + res, res.get("a/b/c/y"));
    res = DescriptorIndexCollector.statLocalDirectory(new File(subdir, "y"));
    assertFalse("found " + res, res.isEmpty());
    assertEquals("found " + res, 1, res.size());
  }

  @Test()
  public void testWrongInputStatLocalDirectory() throws IOException {
    File dir = makeDirs(tmpf.newFolder().toString(), "a", "b");
    SortedMap<String, Long> res = DescriptorIndexCollector
        .statLocalDirectory(new File(dir, "not-there"));
    assertTrue("found " + res, res.isEmpty());
    dir.setReadable(false);
    res = DescriptorIndexCollector.statLocalDirectory(dir);
    assertTrue("found " + res, res.isEmpty());
  }

  @Test(expected = RuntimeException.class)
  public void testMinimalArgs() throws IOException {
    File fakeDir = tmpf.newFolder("fantasy-dir");
    new DescriptorIndexCollector()
        .collectDescriptors(null, new String[]{}, 100L, fakeDir, true);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalMillis() {
    new DescriptorIndexCollector()
        .collectDescriptors("", new String[]{}, -3L, null, false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testIllegalDirectory() throws IOException {
    File fakeDir = tmpf.newFile("fantasy-dir");
    new DescriptorIndexCollector().collectDescriptors(
        null, new String[]{}, 100L, fakeDir, false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNullDirectory() throws IOException {
    new DescriptorIndexCollector().collectDescriptors(
        null, new String[]{}, 100L, null, false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testExistingFile() throws IOException {
    File fakeDir = tmpf.newFile("fantasy-dir");
    new DescriptorIndexCollector()
        .collectDescriptors(null, null, 100L, fakeDir, false);
  }

  @Test()
  public void testExistingDir() throws IOException {
    File dir = tmpf.newFolder();
    dir.setWritable(false);
    SortedMap<String, FileNode> fm = new TreeMap<>();
    fm.put("readonly", new FileNode("w", 2L, "2100-01-01 01:01"));
    thrown.expect(RuntimeException.class);
    thrown.expectMessage("Cannot create dir: " + dir.toString()
        + "/readonly");
    new DescriptorIndexCollector()
        .fetchRemoteFiles(null, fm, 100L, dir, new TreeMap<String, Long>());
  }
}

