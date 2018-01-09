/* Copyright 2016--2018 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.internal;

import org.apache.commons.compress.compressors.bzip2.BZip2CompressorInputStream;
import org.apache.commons.compress.compressors.bzip2.BZip2CompressorOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorInputStream;
import org.apache.commons.compress.compressors.xz.XZCompressorOutputStream;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * These enums provide compression functionality.
 *
 * <p>{@link #findType} determines the compression type by the given extension.
 * Compression can also be zero-compression, which is currently provided by
 * the PLAIN and JSON enums.</p>
 *
 * @since 1.4.0
 */
public enum FileType {

  BZ2(BZip2CompressorInputStream.class, BZip2CompressorOutputStream.class),
  GZ(GzipCompressorInputStream.class, GzipCompressorOutputStream.class),
  JSON(BufferedInputStream.class, BufferedOutputStream.class),
  PLAIN(BufferedInputStream.class, BufferedOutputStream.class),
  XZ(XZCompressorInputStream.class, XZCompressorOutputStream.class);

  private final Class<? extends InputStream> inClass;
  private final Class<? extends OutputStream> outClass;

  FileType(Class<? extends InputStream> in, Class<? extends OutputStream> out) {
    this.inClass = in;
    this.outClass = out;
  }

  /**
   * Returns <code>valueOf</code> or the default enum {@link #PLAIN}, i.e.,
   * this method doesn't throw any exceptions and allways returns a valid enum.
   */
  public static FileType findType(String ext) {
    FileType res = null;
    try {
      res = FileType.valueOf(ext.toUpperCase());
      return res;
    } catch (IllegalArgumentException | NullPointerException re) {
      return PLAIN;
    }
  }

  /** Return the appropriate input stream. */
  public InputStream inputStream(InputStream is) throws Exception {
    return this.inClass.getConstructor(new Class[]{InputStream.class})
        .newInstance(is);
  }

  /** Return the appropriate output stream. */
  public OutputStream outputStream(OutputStream os) throws Exception {
    return this.outClass.getConstructor(new Class[]{OutputStream.class})
        .newInstance(os);
  }
}

