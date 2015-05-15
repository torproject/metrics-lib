/* Copyright 2012--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.SortedMap;

public interface BridgePoolAssignment extends Descriptor {

  /* Return the publication time of this bridge pool assignment list. */
  public long getPublishedMillis();

  /* Return the entries contained in this bridge pool assignment list with
   * map keys being bridge fingerprints and map values being assignment
   * strings, e.g. "https ring=3 flag=stable". */
  public SortedMap<String, String> getEntries();
}

