/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.Stack;
import java.util.TreeMap;

import org.torproject.descriptor.BridgeDescriptorReader;
import org.torproject.descriptor.BridgePoolAssignmentReader;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.RelayDescriptorReader;

public class RelayOrBridgeDescriptorReaderImpl
    implements RelayDescriptorReader, BridgeDescriptorReader,
    BridgePoolAssignmentReader {

  private boolean hasStartedReading = false;

  private List<File> directories = new ArrayList<File>();
  public void addDirectory(File directory) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.directories.add(directory);
  }

  private File historyFile;
  public void setExcludeFiles(File historyFile) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.historyFile = historyFile;
  }

  private boolean failUnrecognizedDescriptorLines = false;
  public void setFailUnrecognizedDescriptorLines() {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.failUnrecognizedDescriptorLines = true;
  }

  public Iterator<DescriptorFile> readDescriptors() {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Initiating reading is only "
          + "permitted once.");
    }
    this.hasStartedReading = true;
    BlockingIteratorImpl<DescriptorFile> descriptorQueue =
        new BlockingIteratorImpl<DescriptorFile>();
    DescriptorReader reader = new DescriptorReader(this.directories,
        descriptorQueue, this.historyFile,
        this.failUnrecognizedDescriptorLines);
    new Thread(reader).start();
    return descriptorQueue;
  }

  private static class DescriptorReader implements Runnable {
    private List<File> directories;
    private BlockingIteratorImpl<DescriptorFile> descriptorQueue;
    private File historyFile;
    private boolean failUnrecognizedDescriptorLines;
    private DescriptorReader(List<File> directories,
        BlockingIteratorImpl<DescriptorFile> descriptorQueue,
        File historyFile, boolean failUnrecognizedDescriptorLines) {
      this.directories = directories;
      this.descriptorQueue = descriptorQueue;
      this.historyFile = historyFile;
      this.failUnrecognizedDescriptorLines =
          failUnrecognizedDescriptorLines;
    }
    public void run() {
      this.readOldHistory();
      this.readDescriptors();
      this.writeNewHistory();
    }
    private SortedMap<String, Long>
        oldHistory = new TreeMap<String, Long>(),
        newHistory = new TreeMap<String, Long>();
    private void readOldHistory() {
      if (this.historyFile == null) {
        return;
      }
      try {
        BufferedReader br = new BufferedReader(new FileReader(
            this.historyFile));
        String line;
        while ((line = br.readLine()) != null) {
          if (!line.contains(" ")) {
            /* TODO Handle this problem? */
            continue;
          }
          long lastModifiedMillis = Long.parseLong(line.substring(0,
              line.indexOf(" ")));
          String absolutePath = line.substring(line.indexOf(" ") + 1);
          this.oldHistory.put(absolutePath, lastModifiedMillis);
        }
        br.close();
      } catch (IOException e) {
        /* TODO Handle this exception. */
      } catch (NumberFormatException e) {
        /* TODO Handle this exception. */
      }
    }
    private void writeNewHistory() {
      if (this.historyFile == null) {
        return;
      }
      try {
        if (this.historyFile.getParentFile() != null) {
          this.historyFile.getParentFile().mkdirs();
        }
        BufferedWriter bw = new BufferedWriter(new FileWriter(
            this.historyFile));
        for (Map.Entry<String, Long> e : this.newHistory.entrySet()) {
          String absolutePath = e.getKey();
          long lastModifiedMillis = e.getValue();
          bw.write(String.valueOf(lastModifiedMillis) + " " + absolutePath
              + "\n");
        }
        bw.close();
      } catch (IOException e) {
        /* TODO Handle this exception. */
      }
    }
    private void readDescriptors() {
      for (File directory : this.directories) {
        Stack<File> files = new Stack<File>();
        files.add(directory);
        boolean abortReading = false;
        while (!abortReading && !files.isEmpty()) {
          File file = files.pop();
          if (file.isDirectory()) {
            files.addAll(Arrays.asList(file.listFiles()));
          } else {
            String absolutePath = file.getAbsolutePath();
            long lastModifiedMillis = file.lastModified();
            this.newHistory.put(absolutePath, lastModifiedMillis);
            if (this.oldHistory.containsKey(absolutePath) &&
                this.oldHistory.get(absolutePath) == lastModifiedMillis) {
              continue;
            }
            DescriptorFileImpl descriptorFile = new DescriptorFileImpl();
            try {
              descriptorFile.setDirectory(directory);
              descriptorFile.setFile(file);
              descriptorFile.setLastModified(lastModifiedMillis);
              descriptorFile.setDescriptors(this.readFile(file));
            } catch (DescriptorParseException e) {
              descriptorFile.setException(e);
            } catch (IOException e) {
              descriptorFile.setException(e);
              abortReading = true;
            }
            this.descriptorQueue.add(descriptorFile);
          }
        }
      }
      this.descriptorQueue.setOutOfDescriptors();
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
      return DescriptorImpl.parseRelayOrBridgeDescriptors(
          rawDescriptorBytes, file.getName(),
          this.failUnrecognizedDescriptorLines);
    }
  }
}

