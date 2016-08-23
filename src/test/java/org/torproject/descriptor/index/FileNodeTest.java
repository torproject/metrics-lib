/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.index;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class FileNodeTest {

  @Test()
  public void testCompare() {
    FileNode fn1 = new FileNode("a1", 1L, "2016-01-01 01:01");
    FileNode fn2 = new FileNode("a2", 1L, "2016-01-01 02:02");
    assertEquals(-1, fn1.compareTo(fn2));
    FileNode fn3 = new FileNode("a1", 100L, "2016-01-01 03:03");
    assertEquals(0, fn1.compareTo(fn3));
    assertEquals(1, fn2.compareTo(fn3));
  }
}

