/* Copyright 2014--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

@SuppressWarnings("serial")
public class ImplementationNotAccessibleException
    extends RuntimeException {

  public ImplementationNotAccessibleException(String string,
      Throwable ex) {
    super(string, ex);
  }
}

