/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;

/* Read bridge pool assignments from one or more local directories. */
public interface BridgePoolAssignmentReader extends DescriptorSource {

  /* Add a local directory to read bridge pool assignments from. */
  public void addDirectory(File directory);
}

