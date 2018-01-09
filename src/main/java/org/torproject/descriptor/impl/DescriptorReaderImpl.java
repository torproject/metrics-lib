/* Copyright 2011--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorReader;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.SortedMap;
import java.util.Stack;
import java.util.TreeMap;

public class DescriptorReaderImpl implements DescriptorReader {

  private static Logger log = LoggerFactory.getLogger(
      DescriptorReaderImpl.class);
  private boolean hasStartedReading = false;

  private File manualSaveHistoryFile;

  @Override
  public void setHistoryFile(File historyFile) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.manualSaveHistoryFile = historyFile;
  }

  private SortedMap<String, Long> excludedFiles;

  @Override
  public void setExcludedFiles(SortedMap<String, Long> excludedFiles) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.excludedFiles = excludedFiles;
  }

  @Override
  public SortedMap<String, Long> getExcludedFiles() {
    if (this.reader == null || !this.reader.hasFinishedReading) {
      throw new IllegalStateException("Operation is not permitted before "
          + "finishing to read.");
    }
    return new TreeMap<>(this.reader.excludedFilesAfter);
  }

  @Override
  public SortedMap<String, Long> getParsedFiles() {
    if (this.reader == null || !this.reader.hasFinishedReading) {
      throw new IllegalStateException("Operation is not permitted before "
          + "finishing to read.");
    }
    return new TreeMap<>(this.reader.parsedFilesAfter);
  }

  private int maxDescriptorsInQueue = 100;

  @Override
  public void setMaxDescriptorsInQueue(int maxDescriptorsInQueue) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Reconfiguration is not permitted "
          + "after starting to read.");
    }
    this.maxDescriptorsInQueue = maxDescriptorsInQueue;
  }

  private DescriptorReaderRunnable reader;

  @Override
  public Iterable<Descriptor> readDescriptors(File... descriptorFiles) {
    if (this.hasStartedReading) {
      throw new IllegalStateException("Initiating reading is only "
          + "permitted once.");
    }
    this.hasStartedReading = true;
    BlockingIteratorImpl<Descriptor> descriptorQueue =
        new BlockingIteratorImpl<>(this.maxDescriptorsInQueue);
    this.reader = new DescriptorReaderRunnable(descriptorFiles, descriptorQueue,
        this.manualSaveHistoryFile, this.excludedFiles);
    Thread readerThread = new Thread(this.reader);
    readerThread.setDaemon(true);
    readerThread.start();
    return descriptorQueue;
  }

  @Override
  public void saveHistoryFile(File historyFile) {
    if (!this.reader.hasFinishedReading) {
      throw new IllegalStateException("Saving history is only permitted after "
          + "reading descriptors.");
    }
    this.reader.writeNewHistory(historyFile);
  }

  private static class DescriptorReaderRunnable implements Runnable {

    private File[] descriptorFiles;

    private BlockingIteratorImpl<Descriptor> descriptorQueue;

    private File autoSaveHistoryFile;

    private File manualSaveHistoryFile;

    private SortedMap<String, Long> excludedFilesBefore = new TreeMap<>();

    private SortedMap<String, Long> excludedFilesAfter = new TreeMap<>();

    private SortedMap<String, Long> parsedFilesAfter = new TreeMap<>();

    private DescriptorParser descriptorParser;

    private boolean hasFinishedReading = false;

    private DescriptorReaderRunnable(File[] descriptorFiles,
        BlockingIteratorImpl<Descriptor> descriptorQueue,
        File manualSaveHistoryFile, SortedMap<String, Long> excludedFiles) {
      this.descriptorFiles = descriptorFiles;
      this.descriptorQueue = descriptorQueue;
      this.autoSaveHistoryFile = autoSaveHistoryFile;
      this.manualSaveHistoryFile = manualSaveHistoryFile;
      if (excludedFiles != null) {
        this.excludedFilesBefore = excludedFiles;
      }
      this.descriptorParser = new DescriptorParserImpl();
    }

    public void run() {
      try {
        this.readOldHistory(this.autoSaveHistoryFile);
        this.readOldHistory(this.manualSaveHistoryFile);
        this.readDescriptorFiles();
        this.hasFinishedReading = true;
      } catch (Throwable t) {
        log.error("Bug: uncaught exception or error while "
            + "reading descriptors: " + t.getMessage(), t);
      } finally {
        if (null != this.descriptorQueue) {
          this.descriptorQueue.setOutOfDescriptors();
        }
      }
      if (this.hasFinishedReading) {
        this.writeNewHistory(this.autoSaveHistoryFile);
      }
    }

    private void readOldHistory(File historyFile) {
      if (historyFile == null || !historyFile.exists()) {
        return;
      }
      List<String> lines = null;
      try {
        lines = Files.readAllLines(historyFile.toPath(),
            StandardCharsets.UTF_8);
        for (String line : lines) {
          if (!line.contains(" ")) {
            log.warn("Unexpected line structure in old history: {}", line);
            continue;
          }
          long lastModifiedMillis = Long.parseLong(line.substring(0,
              line.indexOf(" ")));
          String absolutePath = line.substring(line.indexOf(" ") + 1);
          this.excludedFilesBefore.put(absolutePath, lastModifiedMillis);
        }
      } catch (IOException | NumberFormatException e) {
        log.warn("Trouble reading given history file {}.", historyFile, e);
        return;
      }
    }

    private void writeNewHistory(File historyFile) {
      if (historyFile == null) {
        return;
      }
      if (historyFile.getParentFile() != null) {
        historyFile.getParentFile().mkdirs();
      }
      try (BufferedWriter bw = Files.newBufferedWriter(historyFile.toPath(),
          StandardCharsets.UTF_8)) {
        SortedMap<String, Long> newHistory = new TreeMap<>();
        newHistory.putAll(this.excludedFilesAfter);
        newHistory.putAll(this.parsedFilesAfter);
        for (Map.Entry<String, Long> e : newHistory.entrySet()) {
          String absolutePath = e.getKey();
          String lastModifiedMillis = String.valueOf(e.getValue());
          bw.write(lastModifiedMillis + " " + absolutePath);
          bw.newLine();
        }
      } catch (IOException e) {
        log.warn("Trouble writing new history file '{}'.",
            historyFile, e);
      }
    }

    private void readDescriptorFiles() {
      if (null == this.descriptorFiles) {
        return;
      }
      Stack<File> files = new Stack<>();
      for (File descriptorFile : this.descriptorFiles) {
        if (!descriptorFile.exists()) {
          continue;
        }
        files.add(descriptorFile);
        while (!files.isEmpty()) {
          File file = files.pop();
          try {
            String absolutePath = file.getAbsolutePath();
            long lastModifiedMillis = file.lastModified();
            if (this.excludedFilesBefore.containsKey(absolutePath)
                && this.excludedFilesBefore.get(absolutePath)
                == lastModifiedMillis) {
              this.excludedFilesAfter.put(absolutePath, lastModifiedMillis);
              continue;
            }
            if (file.isDirectory()) {
              files.addAll(Arrays.asList(file.listFiles()));
              continue;
            } else if (file.getName().endsWith(".tar")
                || file.getName().endsWith(".tar.bz2")
                || file.getName().endsWith(".tar.xz")) {
              this.readTarball(file);
            } else {
              this.readDescriptorFile(file);
            }
            this.parsedFilesAfter.put(absolutePath, lastModifiedMillis);
          } catch (IOException e) {
            log.warn("Unable to read descriptor file {}.", file, e);
          }
        }
      }
    }

    private void readTarball(File file) throws IOException {
      FileInputStream in = new FileInputStream(file);
      if (in.available() <= 0) {
        return;
      }
      TarArchiveInputStream tais;
      if (file.getName().endsWith(".tar.bz2")) {
        tais = new TarArchiveInputStream(new BZip2CompressorInputStream(in));
      } else if (file.getName().endsWith(".tar.xz")) {
        tais = new TarArchiveInputStream(new XZCompressorInputStream(in));
      } else if (file.getName().endsWith(".tar")) {
        tais = new TarArchiveInputStream(in);
      } else {
        return;
      }
      BufferedInputStream bis = new BufferedInputStream(tais);
      TarArchiveEntry tae;
      while ((tae = tais.getNextTarEntry()) != null) {
        if (tae.isDirectory()) {
          continue;
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int len;
        byte[] data = new byte[1024];
        while ((len = bis.read(data, 0, 1024)) >= 0) {
          baos.write(data, 0, len);
        }
        byte[] rawDescriptorBytes = baos.toByteArray();
        if (rawDescriptorBytes.length < 1) {
          continue;
        }
        String fileName = tae.getName().substring(
            tae.getName().lastIndexOf("/") + 1);
        for (Descriptor descriptor : this.descriptorParser.parseDescriptors(
            rawDescriptorBytes, file, fileName)) {
          this.descriptorQueue.add(descriptor);
        }
      }
    }

    private void readDescriptorFile(File file) throws IOException {
      byte[] rawDescriptorBytes = Files.readAllBytes(file.toPath());
      for (Descriptor descriptor : this.descriptorParser.parseDescriptors(
          rawDescriptorBytes, file, file.getName())) {
        this.descriptorQueue.add(descriptor);
      }
    }
  }
}

