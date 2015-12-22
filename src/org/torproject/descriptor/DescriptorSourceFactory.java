/* Copyright 2011--2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor;

/* Create descriptor source instances. */
public final class DescriptorSourceFactory {

  /* default implementations */
  public final static String LOADER_DEFAULT =
      "org.torproject.descriptor.impl.DescriptorDownloaderImpl";
  public final static String PARSER_DEFAULT =
      "org.torproject.descriptor.impl.DescriptorParserImpl";
  public final static String READER_DEFAULT =
      "org.torproject.descriptor.impl.DescriptorReaderImpl";
  public final static String COLLECTOR_DEFAULT =
      "org.torproject.descriptor.impl.DescriptorCollectorImpl";

  /* property names */
  public final static String PARSER_PROPERTY = "onionoo.parser";
  public final static String READER_PROPERTY = "onionoo.property";
  public final static String LOADER_PROPERTY = "onionoo.downloader";
  public final static String COLLECTOR_PROPERTY = "onionoo.collector";

  /**
   * Create a descriptor parser.
   */
  public final static DescriptorParser createDescriptorParser() {
    return (DescriptorParser) retrieve(PARSER_PROPERTY);
  }

  /**
   * Create a descriptor reader.
   */
  public final static DescriptorReader createDescriptorReader() {
    return (DescriptorReader) retrieve(READER_PROPERTY);
  }

  /**
   * Create a descriptor downloader.
   */
  public final static DescriptorDownloader createDescriptorDownloader() {
    return (DescriptorDownloader) retrieve(LOADER_PROPERTY);
  }

  /**
   * Create a descriptor collector.
   */
  public final static DescriptorCollector createDescriptorCollector() {
    return (DescriptorCollector) retrieve(COLLECTOR_PROPERTY);
  }

  private final static <T> Object retrieve(String type) {
    Object object;
    String clazzName = null;
    try {
      switch (type) {
      case PARSER_PROPERTY:
        clazzName = System.getProperty(type, PARSER_DEFAULT);
        break;
      case LOADER_PROPERTY:
        clazzName = System.getProperty(type, LOADER_DEFAULT);
        break;
      case READER_PROPERTY:
        clazzName = System.getProperty(type, READER_DEFAULT);
        break;
      case COLLECTOR_PROPERTY:
        clazzName = System.getProperty(type, COLLECTOR_DEFAULT);
        break;
      }
      object = ClassLoader.getSystemClassLoader().loadClass(clazzName).
          newInstance();
    } catch (ClassNotFoundException ex) {
      throw new ImplementationNotAccessibleException("Cannot load class "
          + clazzName + "for type " + type, ex);
    } catch (InstantiationException ex) {
      throw new ImplementationNotAccessibleException("Cannot load class "
          + clazzName + "for type " + type, ex);
    } catch (IllegalAccessException ex) {
      throw new ImplementationNotAccessibleException("Cannot load class "
          + clazzName + "for type " + type, ex);
    }
    return object;
  }
}

