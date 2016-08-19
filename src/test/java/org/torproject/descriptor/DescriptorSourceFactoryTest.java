/* Copyright 2016 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

import static org.torproject.descriptor.DescriptorSourceFactory.*;

import org.torproject.descriptor.DescriptorCollector;
import org.torproject.descriptor.DescriptorDownloader;
import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorReader;
import org.torproject.descriptor.ImplementationNotAccessibleException;
import org.torproject.descriptor.impl.DescriptorCollectorImpl;
import org.torproject.descriptor.impl.DescriptorDownloaderImpl;
import org.torproject.descriptor.impl.DescriptorParserImpl;
import org.torproject.descriptor.impl.DescriptorReaderImpl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.lang.reflect.Method;
import java.lang.reflect.InvocationTargetException;

public class DescriptorSourceFactoryTest {

  private final static String[] properties = new String[]{
      COLLECTOR_PROPERTY, DOWNLOADER_PROPERTY, PARSER_PROPERTY, READER_PROPERTY};
  private final static String[] defaults = new String[]{
      COLLECTOR_DEFAULT, DOWNLOADER_DEFAULT, PARSER_DEFAULT, READER_DEFAULT};

  @Test()
  public void testDefaults() {
    setProperties(defaults);
    DescriptorCollector dc = DescriptorSourceFactory.createDescriptorCollector();
    assertTrue(dc instanceof DescriptorCollectorImpl);
    DescriptorDownloader dd = DescriptorSourceFactory.createDescriptorDownloader();
    assertTrue(dd instanceof DescriptorDownloaderImpl);
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    assertTrue(dp instanceof DescriptorParserImpl);
    DescriptorReader dr = DescriptorSourceFactory.createDescriptorReader();
    assertTrue(dr instanceof DescriptorReaderImpl);
  }

  private void setProperties(String[] vals) {
    for (int k = 0; k < properties.length; k++) {
      System.setProperty(properties[k], vals[k]);
    }
  }

  @Test(expected = ImplementationNotAccessibleException.class)
  public void testException() {
    System.setProperty(COLLECTOR_PROPERTY ,
        "no.implementation.available.X");
    DescriptorSourceFactory.createDescriptorCollector();
  }

  @Test()
  public void testUnknownPropertyException() {
    setProperties(defaults);
    try {
      Method retrieve = DescriptorSourceFactory.class
          .getDeclaredMethod("retrieve", String.class);
      retrieve.setAccessible(true);
      retrieve.invoke(null, "unknown.property");
    } catch (InvocationTargetException ite) {
      if(ite.getCause() instanceof ImplementationNotAccessibleException) {
        return;
      } else {
        fail("Cause was " + ite.getCause()
            + ", but expected InvocationTargetException.");
      }
    } catch (Throwable t) {
      fail("Caught " + t + ", but expected InvocationTargetException.");
    }
  }

  @Test()
  public void testProperties() {
    setProperties(new String[]{
        "org.torproject.descriptor.DummyCollectorImplementation",
        "org.torproject.descriptor.DummyDownloaderImplementation",
        "org.torproject.descriptor.DummyParserImplementation",
        "org.torproject.descriptor.DummyReaderImplementation",
      });
    DescriptorCollector dc = DescriptorSourceFactory.createDescriptorCollector();
    assertTrue(dc instanceof DummyCollectorImplementation);
    assertEquals(1, DummyCollectorImplementation.count);
    DescriptorDownloader dd = DescriptorSourceFactory.createDescriptorDownloader();
    assertTrue(dd instanceof DummyDownloaderImplementation);
    assertEquals(1, DummyDownloaderImplementation.count);
    DescriptorParser dp = DescriptorSourceFactory.createDescriptorParser();
    assertTrue(dp instanceof DummyParserImplementation);
    assertEquals(1, DummyParserImplementation.count);
    DescriptorReader dr = DescriptorSourceFactory.createDescriptorReader();
    assertTrue(dr instanceof DummyReaderImplementation);
    assertEquals(1, DummyReaderImplementation.count);
  }

}

class DummyCollectorImplementation extends DescriptorCollectorImpl {
  static int count;
  public DummyCollectorImplementation() {
    count++;
  }
}

class DummyDownloaderImplementation extends DescriptorDownloaderImpl {
  static int count;
  public DummyDownloaderImplementation() {
    count++;
  }
}

class DummyParserImplementation extends DescriptorParserImpl {
  static int count;
  public DummyParserImplementation() {
    count++;
  }
}

class DummyReaderImplementation extends DescriptorReaderImpl {
  static int count;
  public DummyReaderImplementation() {
    count++;
  }
}
