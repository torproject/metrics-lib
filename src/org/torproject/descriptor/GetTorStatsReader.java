/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;

/* Read GetTor stats from one or more local directories. */
public interface GetTorStatsReader extends DescriptorSource {

  /* Add a local directory to read GetTor stats files from. */
  public void addDirectory(File directory);

}

