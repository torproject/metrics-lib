/* Copyright 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import java.util.List;

/* Contains a v1 signed directory. */
public interface RelayDirectory extends Descriptor {

  /* Return the published time in milliseconds. */
  public long getPublishedMillis();

  /* Return the directory signing key digest. */
  public String getDirSigningKey();

  /* Return recommended software versions or null if the directory doesn't
   * list recommended software. */
  public List<String> getRecommendedSoftware();

  /* Return the directory signature. */
  public String getDirectorySignature();

  /* Return router status entries, one for each contained relay. */
  public List<RouterStatusEntry> getRouterStatusEntries();

  /* Return a list of server descriptors contained in the signed
   * directory. */
  public List<ServerDescriptor> getServerDescriptors();

  /* Return a (very likely empty) list of exceptions from parsing the
   * contained server descriptors. */
  public List<Exception> getServerDescriptorParseExceptions();

  /* Return the directory nickname. */
  public String getNickname();

  /* Return the directory digest that the directory authority used to sign
   * the directory. */
  public String getDirectoryDigest();
}

