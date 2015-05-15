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

  /* property names */
  public final static String PARSER_PROPERTY = "onionoo.parser";
  public final static String READER_PROPERTY = "onionoo.property";
  public final static String LOADER_PROPERTY = "onionoo.downloader";

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

  private final static <T> Object retrieve(String type) {
    Object object;
    String clazzName = null;
    try {
      if (PARSER_PROPERTY.equals(type)) {
        clazzName = System.getProperty(type, PARSER_DEFAULT);
      } else if (LOADER_PROPERTY.equals(type)) {
        clazzName = System.getProperty(type, LOADER_DEFAULT);
      } else if (READER_PROPERTY.equals(type)) {
        clazzName = System.getProperty(type, READER_DEFAULT);
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

