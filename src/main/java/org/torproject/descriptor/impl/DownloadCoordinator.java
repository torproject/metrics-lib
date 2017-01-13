/* Copyright 2011--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

public interface DownloadCoordinator {

  public DescriptorRequestImpl createRequest(String nickname);

  public void deliverResponse(DescriptorRequestImpl request);
}
