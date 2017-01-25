/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertEquals;

import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.DescriptorReader;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Iterator;
import java.util.SortedMap;
import java.util.TreeMap;

/** Tests the descriptor reader by preparing a temporary folder with two input
 * descriptor files and a parse history file, running the reader with different
 * configurations, and verifying the reader's state afterwards. */
public class DescriptorReaderImplTest {

  /** Temporary folder containing all files for this test. */
  @Rule
  public TemporaryFolder temporaryFolder = new TemporaryFolder();

  /** Directory containing two input descriptor files. */
  private File inputDirectory;

  /** Parse history map. */
  private SortedMap<String, Long> historyMap;

  /** Parse history file. */
  private File historyFile;

  /** Descriptor reader used in this test. */
  private DescriptorReader descriptorReader = new DescriptorReaderImpl();

  /** Prepares the temporary folder and writes files to it for this test. */
  @Before
  public void createTemporaryFolderAndContents() throws IOException {
    this.inputDirectory = this.temporaryFolder.newFolder("in");
    File fafaFile = new File(this.inputDirectory, "fafa");
    File ffe0File = new File(this.inputDirectory, "ffe0");
    Files.copy(getClass().getClassLoader().getResource(
        "fafaa9366f010db805de13a4b7348aba2acb6f17").openStream(),
        fafaFile.toPath());
    Files.copy(getClass().getClassLoader().getResource(
        "ffe08f10c0ca5198f7cfa8787651bee538f4f7e0").openStream(),
        ffe0File.toPath());
    this.historyMap = new TreeMap<>();
    this.historyMap.put(fafaFile.getAbsolutePath(), fafaFile.lastModified());
    String parseHistoryContents = String.format("%d %s%n",
        fafaFile.lastModified(), fafaFile.getAbsolutePath());
    this.historyFile = this.temporaryFolder.newFile("history");
    Files.write(this.historyFile.toPath(),
        parseHistoryContents.getBytes(StandardCharsets.UTF_8));
  }

  private int readAllDescriptors() {
    Iterator<DescriptorFile> descriptorFiles =
        this.descriptorReader.readDescriptors();
    int count = 0;
    while (descriptorFiles.hasNext()) {
      count++;
      descriptorFiles.next();
    }
    return count;
  }

  private void assertExcludedFilesParsedFilesAndHistoryFileLines(
      int expectedExcludedFiles, int expectedParsedFiles,
      int expectedHistoryFileLines) throws IOException {
    assertEquals(expectedExcludedFiles,
        this.descriptorReader.getExcludedFiles().size());
    assertEquals(expectedParsedFiles,
        this.descriptorReader.getParsedFiles().size());
    assertEquals(expectedHistoryFileLines,
        Files.readAllLines(this.historyFile.toPath(),
        StandardCharsets.UTF_8).size());
  }

  @Test
  public void testDescriptors() throws IOException {
    this.descriptorReader.addDirectory(this.inputDirectory);
    this.readAllDescriptors();
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 2, 1);
  }

  @Test
  public void testNoDescriptors() throws IOException {
    this.readAllDescriptors();
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 0, 1);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testSetExcludeFilesDescriptors() throws InterruptedException,
      IOException {
    this.descriptorReader.setExcludeFiles(this.historyFile);
    this.descriptorReader.addDirectory(this.inputDirectory);
    this.readAllDescriptors();
    Thread.sleep(100L); /* It may take a moment to write the history file. */
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(1, 1, 2);
  }

  @Test
  @SuppressWarnings("deprecation")
  public void testSetExcludeFilesNoDescriptors() throws InterruptedException,
      IOException {
    this.descriptorReader.setExcludeFiles(this.historyFile);
    this.readAllDescriptors();
    Thread.sleep(100L); /* It may take a moment to write the history file. */
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 0, 0);
  }

  @Test
  public void testSetHistoryFileDescriptors() throws IOException {
    this.descriptorReader.setHistoryFile(this.historyFile);
    this.descriptorReader.addDirectory(this.inputDirectory);
    this.readAllDescriptors();
    descriptorReader.saveHistoryFile(this.historyFile);
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(1, 1, 2);
  }

  @Test
  public void testSetHistoryFileNoDescriptors() throws IOException {
    this.descriptorReader.setHistoryFile(this.historyFile);
    this.readAllDescriptors();
    this.descriptorReader.saveHistoryFile(this.historyFile);
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 0, 0);
  }

  @Test
  public void testSetExcludedFilesDescriptors() throws IOException {
    this.descriptorReader.setExcludedFiles(this.historyMap);
    this.descriptorReader.addDirectory(this.inputDirectory);
    this.readAllDescriptors();
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(1, 1, 1);
  }

  @Test
  public void testSetExcludedFilesNoDescriptors() throws IOException {
    this.descriptorReader.setExcludedFiles(this.historyMap);
    this.readAllDescriptors();
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 0, 1);
  }

  @Test
  public void testSetHistoryCorruptFile() throws IOException {
    File corruptHistoryFile = this.temporaryFolder.newFile("corruptHistory");
    Files.write(corruptHistoryFile.toPath(),"1293145200000  \n   ".getBytes());
    this.descriptorReader.setHistoryFile(corruptHistoryFile);
    this.descriptorReader.addDirectory(this.inputDirectory);
    int count = this.readAllDescriptors();
    assertEquals("Two files should have been parsed.", 2, count);
    descriptorReader.saveHistoryFile(this.historyFile);
    this.assertExcludedFilesParsedFilesAndHistoryFileLines(0, 2, 2);
  }

}

