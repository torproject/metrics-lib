/* Copyright 2016--2017 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.torproject.descriptor.DescriptorSourceFactory.COLLECTOR_DEFAULT;
import static org.torproject.descriptor.DescriptorSourceFactory.COLLECTOR_PROPERTY;
import static org.torproject.descriptor.DescriptorSourceFactory.DOWNLOADER_DEFAULT;
import static org.torproject.descriptor.DescriptorSourceFactory.DOWNLOADER_PROPERTY;
import static org.torproject.descriptor.DescriptorSourceFactory.PARSER_DEFAULT;
import static org.torproject.descriptor.DescriptorSourceFactory.PARSER_PROPERTY;
import static org.torproject.descriptor.DescriptorSourceFactory.READER_DEFAULT;
import static org.torproject.descriptor.DescriptorSourceFactory.READER_PROPERTY;

import org.torproject.descriptor.impl.DescriptorDownloaderImpl;
import org.torproject.descriptor.impl.DescriptorParserImpl;
import org.torproject.descriptor.impl.DescriptorReaderImpl;
import org.torproject.descriptor.index.DescriptorIndexCollector;

import org.junit.Test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

public class DescriptorSourceFactoryTest {

  private static final String[] properties = new String[] { COLLECTOR_PROPERTY,
      DOWNLOADER_PROPERTY, PARSER_PROPERTY, READER_PROPERTY };

  private static final String[] defaults = new String[] { COLLECTOR_DEFAULT,
      DOWNLOADER_DEFAULT, PARSER_DEFAULT, READER_DEFAULT };

  @Test()
  public void testDefaults() {
    setProperties(defaults);
    DescriptorCollector dc =
        DescriptorSourceFactory.createDescriptorCollector();
    assertTrue(dc instanceof DescriptorIndexCollector);
    DescriptorDownloader dd =
        DescriptorSourceFactory.createDescriptorDownloader();
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
      if (ite.getCause() instanceof ImplementationNotAccessibleException) {
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
    setProperties(new String[] {
        "org.torproject.descriptor.DummyCollectorImplementation",
        "org.torproject.descriptor.DummyDownloaderImplementation",
        "org.torproject.descriptor.DummyParserImplementation",
        "org.torproject.descriptor.DummyReaderImplementation" });
    DescriptorCollector dc =
        DescriptorSourceFactory.createDescriptorCollector();
    assertTrue(dc instanceof DummyCollectorImplementation);
    assertEquals(1, DummyCollectorImplementation.count);
    DescriptorDownloader dd =
        DescriptorSourceFactory.createDescriptorDownloader();
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
