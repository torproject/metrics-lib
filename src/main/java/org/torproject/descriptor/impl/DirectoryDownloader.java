/* Copyright 2011--2016 The Tor Project
 * See LICENSE for licensing information */

package org.torproject.descriptor.impl;

import org.torproject.descriptor.DescriptorParser;
import org.torproject.descriptor.DescriptorSourceFactory;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.zip.InflaterInputStream;

/* Download descriptors from one directory authority or mirror.  First,
 * ask the coordinator thread to create a request, run it, and deliver
 * the response.  Repeat until the coordinator thread says there are no
 * further requests to make. */
public class DirectoryDownloader implements Runnable {

  private String nickname;

  private String ipPort;

  private DescriptorParser descriptorParser;

  protected DirectoryDownloader(String nickname, String ip, int dirPort) {
    this.nickname = nickname;
    this.ipPort = ip + ":" + String.valueOf(dirPort);
    this.descriptorParser =
        DescriptorSourceFactory.createDescriptorParser();
  }

  private DownloadCoordinator downloadCoordinator;

  protected void setDownloadCoordinator(
      DownloadCoordinator downloadCoordinator) {
    this.downloadCoordinator = downloadCoordinator;
  }

  private long connectTimeout;

  protected void setConnectTimeout(long connectTimeout) {
    this.connectTimeout = connectTimeout;
  }

  private long readTimeout;

  protected void setReadTimeout(long readTimeout) {
    this.readTimeout = readTimeout;
  }

  protected void setFailUnrecognizedDescriptorLines(
      boolean failUnrecognizedDescriptorLines) {
    this.descriptorParser.setFailUnrecognizedDescriptorLines(
        failUnrecognizedDescriptorLines);
  }

  @Override
  public void run() {
    boolean keepRunning = true;
    do {
      DescriptorRequestImpl request =
          this.downloadCoordinator.createRequest(this.nickname);
      if (request != null) {
        String urlString = "http://" + this.ipPort
            + request.getRequestedResource();
        request.setRequestStart(System.currentTimeMillis());
        HttpURLConnection huc = null;
        try {
          URL url = new URL(urlString);
          huc = (HttpURLConnection) url.openConnection();
          huc.setConnectTimeout((int) this.connectTimeout);
          huc.setReadTimeout((int) this.readTimeout);
          huc.setRequestMethod("GET");
          huc.connect();
          int responseCode = huc.getResponseCode();
          request.setResponseCode(responseCode);
          if (responseCode == 200) {
            BufferedInputStream in = new BufferedInputStream(
                new InflaterInputStream(huc.getInputStream()));
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            int len;
            byte[] data = new byte[8192];
            while ((len = in.read(data, 0, 8192)) >= 0) {
              baos.write(data, 0, len);
            }
            in.close();
            byte[] responseBytes = baos.toByteArray();
            request.setResponseBytes(responseBytes);
            request.setRequestEnd(System.currentTimeMillis());
            request.setDescriptors(this.descriptorParser.parseDescriptors(
                responseBytes, null));
          }
        } catch (Exception e) {
          request.setException(e);
          if (huc != null) {
            huc.disconnect();
          }
          /* Stop downloading from this directory if there are any
           * problems, e.g., refused connections. */
          keepRunning = false;
        }
        this.downloadCoordinator.deliverResponse(request);
      } else {
        keepRunning = false;
      }
    } while (keepRunning);
  }
}

