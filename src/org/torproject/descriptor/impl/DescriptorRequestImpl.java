/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.List;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorRequest;

public class DescriptorRequestImpl implements DescriptorRequest {

  private String requestedResource;
  protected void setRequestedResource(String requestedResource) {
    this.requestedResource = requestedResource;
  }
  protected String getRequestedResource() {
    return this.requestedResource;
  }

  private String descriptorType;
  protected void setDescriptorType(String descriptorType) {
    this.descriptorType = descriptorType;
  }
  protected String getDescriptorType() {
    return this.descriptorType;
  }

  private byte[] responseBytes;
  protected byte[] getResponseBytes() {
    return this.responseBytes;
  }
  protected void setResponseBytes(byte[] responseBytes) {
    this.responseBytes = responseBytes;
  }

  private String requestUrl;
  public String getRequestUrl() {
    return this.requestUrl;
  }

  private String directoryNickname;
  protected void setDirectoryNickname(String directoryNickname) {
    this.directoryNickname = directoryNickname;
  }
  public String getDirectoryNickname() {
    return this.directoryNickname;
  }

  private int responseCode;
  protected void setResponseCode(int responseCode) {
    this.responseCode = responseCode;
  }
  public int getResponseCode() {
    return this.responseCode;
  }

  private long requestStart;
  protected void setRequestStart(long requestStart) {
    this.requestStart = requestStart;
  }
  public long getRequestStart() {
    return this.requestStart;
  }

  private long requestEnd;
  protected void setRequestEnd(long requestEnd) {
    this.requestEnd = requestEnd;
  }
  public long getRequestEnd() {
    return this.requestEnd;
  }

  private boolean requestTimeoutHasExpired;
  public boolean requestTimeoutHasExpired() {
    return this.requestTimeoutHasExpired;
  }

  private boolean globalTimeoutHasExpired;
  public boolean globalTimeoutHasExpired() {
    return this.globalTimeoutHasExpired;
  }

  private List<Descriptor> descriptors;
  protected void setDescriptors(List<Descriptor> descriptors) {
    this.descriptors = descriptors;
  }
  public List<Descriptor> getDescriptors() {
    return this.descriptors;
  }

  private Exception exception;
  protected void setException(Exception exception) {
    this.exception = exception;
  }
  public Exception getException() {
    return this.exception;
  }
}

