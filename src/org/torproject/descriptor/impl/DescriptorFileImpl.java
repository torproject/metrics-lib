/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;

public class DescriptorFileImpl implements DescriptorFile {

  private File directory;
  protected void setDirectory(File directory) {
    this.directory = directory;
  }
  public File getDirectory() {
    return this.directory;
  }

  private File tarball;
  protected void setTarball(File tarball) {
    this.tarball = tarball;
  }
  public File getTarball() {
    return this.tarball;
  }

  private File file;
  protected void setFile(File file) {
    this.file = file;
  }
  public File getFile() {
    return this.file;
  }

  private String fileName;
  protected void setFileName(String fileName) {
    this.fileName = fileName;
  }
  public String getFileName() {
    return this.fileName;
  }

  private long lastModified;
  protected void setLastModified(long lastModified) {
    this.lastModified = lastModified;
  }
  public long getLastModified() {
    return this.lastModified;
  }

  private List<Descriptor> descriptors;
  protected void setDescriptors(List<Descriptor> descriptors) {
    this.descriptors = descriptors;
  }
  public List<Descriptor> getDescriptors() {
    return this.descriptors == null ? new ArrayList<Descriptor>() :
      new ArrayList<Descriptor>(this.descriptors);
  }

  private Exception exception;
  protected void setException(Exception exception) {
    this.exception = exception;
  }
  public Exception getException() {
    return this.exception;
  }
}

