/* Copyright 2016--2020 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

import java.util.SortedSet;
import java.util.TreeSet;

public class DirectoryNodeTest {

  @Test
  public void testCompare() {
    DirectoryNode dn1 = new DirectoryNode("a1", null, null);
    DirectoryNode dn2 = new DirectoryNode("a2", null,
        new TreeSet<>());
    assertEquals(-1, dn1.compareTo(dn2));
    DirectoryNode dn3 = new DirectoryNode("a1", new TreeSet<>(),
        new TreeSet<>());
    assertEquals(0, dn1.compareTo(dn3));
    assertEquals(1, dn2.compareTo(dn3));
  }

  @Test
  public void testFind() {
    FileNode fnx = new FileNode("x", 0L, "2000-01-01 01:01");
    SortedSet<FileNode> fm = new TreeSet<>();
    fm.add(fnx);
    DirectoryNode dnb = new DirectoryNode("b", fm, null);
    SortedSet<DirectoryNode> dm1 = new TreeSet<>();
    dm1.add(dnb);
    DirectoryNode dna = new DirectoryNode("a", null, dm1);
    SortedSet<DirectoryNode> dm2 = new TreeSet<>();
    dm2.add(dna);
    assertNull(IndexNode.findPathIn("b", dm2));
    assertEquals(dnb, IndexNode.findPathIn("b", dm1));
  }
}

