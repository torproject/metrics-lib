/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;

/* Read Torperf data files from one or more local directories. */
public interface TorperfDataReader extends DescriptorSource {

  /* Add a local directory to read Torperf data files from. */
  public void addDirectory(File directory);

}

