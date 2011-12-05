/* Copyright 2011 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.io.File;
import java.util.Map;
import java.util.Set;

/* Read bridge descriptors from one or more local directories. */
public interface DescriptorSource {

  /* Initialize the descriptor source and make descriptors available in
   * the returned data store.  This method can only be run once.  The
   * caller will be blocked until descriptors have been made available. */
  public DescriptorStore initialize();
}

