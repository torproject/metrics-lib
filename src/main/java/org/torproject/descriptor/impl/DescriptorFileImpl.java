/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class DescriptorFileImpl implements DescriptorFile {

  private File directory;

  protected void setDirectory(File directory) {
    this.directory = directory;
  }

  @Override
  public File getDirectory() {
    return this.directory;
  }

  private File tarball;

  protected void setTarball(File tarball) {
    this.tarball = tarball;
  }

  @Override
  public File getTarball() {
    return this.tarball;
  }

  private File file;

  protected void setFile(File file) {
    this.file = file;
  }

  @Override
  public File getFile() {
    return this.file;
  }

  private String fileName;

  protected void setFileName(String fileName) {
    this.fileName = fileName;
  }

  @Override
  public String getFileName() {
    return this.fileName;
  }

  private long lastModified;

  protected void setLastModified(long lastModified) {
    this.lastModified = lastModified;
  }

  @Override
  public long getLastModified() {
    return this.lastModified;
  }

  private List<Descriptor> descriptors;

  protected void setDescriptors(List<Descriptor> descriptors) {
    this.descriptors = descriptors;
  }

  @Override
  public List<Descriptor> getDescriptors() {
    return this.descriptors == null ? new ArrayList<Descriptor>()
        : new ArrayList<>(this.descriptors);
  }

  private Exception exception;

  protected void setException(Exception exception) {
    this.exception = exception;
  }

  @Override
  public Exception getException() {
    return this.exception;
  }
}

