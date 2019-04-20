/* Copyright 2016--2019 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * Builds a test descriptor by concatenating the given lines with newlines and
 * writing the output to a byte array.
 */
class TestDescriptorBuilder extends ArrayList<String> {

  /**
   * Initializes a new test descriptor builder with the given lines.
   */
  TestDescriptorBuilder(String ... lines) {
    this.addAll(Arrays.asList(lines));
  }

  /**
   * Appends the given line or lines.
   */
  TestDescriptorBuilder appendLines(String ... lines) {
    this.addAll(Arrays.asList(lines));
    return this;
  }

  /**
   * Removes the given line, or fails if that line cannot be found.
   */
  TestDescriptorBuilder removeLine(String line) {
    if (!this.remove(line)) {
      fail("Line not contained: " + line);
    }
    return this;
  }

  /**
   * Removes all but the given line, or fails if that line cannot be found.
   */
  TestDescriptorBuilder removeAllExcept(String line) {
    assertTrue("Line not contained: " + line, this.contains(line));
    this.retainAll(Arrays.asList(line));
    return this;
  }

  /**
   * Finds the first line that starts with the given line start and inserts the
   * given lines before it, or fails if no line can be found with that line
   * start.
   */
  TestDescriptorBuilder insertBeforeLineStartingWith(String lineStart,
      String ... linesToInsert) {
    for (int i = 0; i < this.size(); i++) {
      if (this.get(i).startsWith(lineStart)) {
        this.addAll(i, Arrays.asList(linesToInsert));
        return this;
      }
    }
    fail("Line start not found: " + lineStart);
    return this;
  }

  /**
   * Finds the first line that starts with the given line start and replaces
   * that line and possibly subsequent lines, or fails if no line can be found
   * with that line start or there are not enough lines left to replace.
   */
  TestDescriptorBuilder replaceLineStartingWith(String lineStart,
      String ... linesToReplace) {
    for (int i = 0; i < this.size(); i++) {
      if (this.get(i).startsWith(lineStart)) {
        for (int j = 0; j < linesToReplace.length; j++) {
          assertTrue("Not enough lines left to replace.",
              this.size() > i + j);
          this.set(i + j, linesToReplace[j]);
        }
        return this;
      }
    }
    fail("Line start not found: " + lineStart);
    return this;
  }

  /**
   * Finds the first line that starts with the given line start and truncates
   * that line and possibly subsequent lines, or fails if no line can be found
   * with that line start.
   */
  TestDescriptorBuilder truncateAtLineStartingWith(String lineStart) {
    for (int i = 0; i < this.size(); i++) {
      if (this.get(i).startsWith(lineStart)) {
        while (this.size() > i) {
          this.remove(i);
        }
        return this;
      }
    }
    fail("Line start not found: " + lineStart);
    return this;
  }

  /**
   * Concatenates all descriptor lines with newlines and returns the raw
   * descriptor bytes as byte array.
   */
  byte[] build() {
    StringBuilder sb = new StringBuilder();
    for (String line : this) {
      sb.append(line).append('\n');
    }
    return sb.toString().getBytes();
  }
}

