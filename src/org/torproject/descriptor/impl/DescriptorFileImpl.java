/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.File;
import java.util.List;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;

public class DescriptorFileImpl implements DescriptorFile {

  private File directory;
  protected void setDirectory(File directory) {
    this.directory = directory;
  }
  public File getDirectory() {
    return this.file;
  }

  private File file;
  protected void setFile(File file) {
    this.file = file;
  }
  public File getFile() {
    return this.file;
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
    return this.descriptors;
  }
}

