/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.BridgeDescriptorReader;

public class BridgeDescriptorReaderImpl
    implements BridgeDescriptorReader {

  private List<File> directories = new ArrayList<File>();
  public void addDirectory(File directory) {
    this.directories.add(directory);
  }

  public void setExcludeFile(File fileToExclude) {
    throw new UnsupportedOperationException("Not implemented yet.");
    /* TODO Implement me. */
  }

  public void setExcludeFiles(Set<File> filesToExclude) {
    throw new UnsupportedOperationException("Not implemented yet.");
    /* TODO Implement me. */
  }

  public Iterator<DescriptorFile> readDescriptors() {
    BlockingIteratorImpl<DescriptorFile> descriptorQueue =
        new BlockingIteratorImpl<DescriptorFile>();
    DescriptorReader reader = new DescriptorReader(this.directories,
        descriptorQueue);
    new Thread(reader).start();
    return descriptorQueue;
  }

  private static class DescriptorReader implements Runnable {
    private List<File> directories;
    private BlockingIteratorImpl<DescriptorFile> descriptorQueue;
    private DescriptorReader(List<File> directories,
        BlockingIteratorImpl<DescriptorFile> descriptorQueue) {
      this.directories = directories;
      this.descriptorQueue = descriptorQueue;
    }
    public void run() {
      for (File directory : this.directories) {
        try {
          Stack<File> files = new Stack<File>();
          files.add(directory);
          while (!files.isEmpty()) {
            File file = files.pop();
            if (file.isDirectory()) {
              files.addAll(Arrays.asList(file.listFiles()));
            } else {
              try {
                List<Descriptor> parsedDescriptors = this.readFile(file);
                DescriptorFileImpl descriptorFile =
                    new DescriptorFileImpl();
                descriptorFile.setDirectory(directory);
                descriptorFile.setFile(file);
                descriptorFile.setLastModified(file.lastModified());
                descriptorFile.setDescriptors(parsedDescriptors);
                this.descriptorQueue.add(descriptorFile);
              } catch (DescriptorParseException e) {
                /* TODO Handle me. */
              }
            }
          }
        } catch (IOException e) {
          System.err.println("Error while reading descriptors in '"
              + directory.getAbsolutePath() + "'.");
          /* TODO Handle this exception somehow. */
        } finally {
          this.descriptorQueue.setOutOfDescriptors();
        }
      }
    }
    private List<Descriptor> readFile(File file) throws IOException,
        DescriptorParseException {
      FileInputStream fis = new FileInputStream(file);
      BufferedInputStream bis = new BufferedInputStream(fis);
      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      int len;
      byte[] data = new byte[1024];
      while ((len = bis.read(data, 0, 1024)) >= 0) {
        baos.write(data, 0, len);
      }
      bis.close();
      byte[] rawDescriptorBytes = baos.toByteArray();
      return DescriptorImpl.parseBridgeDescriptors(rawDescriptorBytes,
          file.getName());
    }
  }
}

