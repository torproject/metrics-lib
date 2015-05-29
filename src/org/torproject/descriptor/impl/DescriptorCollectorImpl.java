/* Copyright 2015 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Map;
import java.util.Scanner;
import java.util.SortedMap;
import java.util.SortedSet;
import java.util.Stack;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;

import org.torproject.descriptor.DescriptorCollector;

public class DescriptorCollectorImpl implements DescriptorCollector {

  @Override
  public void collectDescriptors(String collecTorBaseUrl,
      String[] remoteDirectories, long minLastModified,
      File localDirectory, boolean deleteExtraneousLocalFiles) {
    collecTorBaseUrl = collecTorBaseUrl.endsWith("/")
        ? collecTorBaseUrl.substring(0, collecTorBaseUrl.length() - 1)
        : collecTorBaseUrl;
    if (minLastModified < 0) {
      throw new IllegalArgumentException("A negative minimum "
          + "last-modified time is not permitted.");
    }
    if (localDirectory.exists() && !localDirectory.isDirectory()) {
      throw new IllegalArgumentException("Local directory already exists "
          + "and is not a directory.");
    }
    SortedMap<String, Long> localFiles =
        this.statLocalDirectory(localDirectory);
    SortedMap<String, String> fetchedDirectoryListings =
        this.fetchRemoteDirectories(collecTorBaseUrl, remoteDirectories);
    SortedSet<String> parsedDirectories = new TreeSet<String>();
    SortedMap<String, Long> remoteFiles = new TreeMap<String, Long>();
    for (Map.Entry<String, String> e :
        fetchedDirectoryListings.entrySet()) {
      String remoteDirectory = e.getKey();
      String directoryListing = e.getValue();
      SortedMap<String, Long> parsedRemoteFiles =
          this.parseDirectoryListing(remoteDirectory, directoryListing);
      if (parsedRemoteFiles == null) {
        continue;
      }
      parsedDirectories.add(remoteDirectory);
      remoteFiles.putAll(parsedRemoteFiles);
    }
    this.fetchRemoteFiles(collecTorBaseUrl, remoteFiles, minLastModified,
        localDirectory, localFiles);
    if (deleteExtraneousLocalFiles) {
      this.deleteExtraneousLocalFiles(parsedDirectories, remoteFiles,
          localDirectory, localFiles);
    }
  }

  SortedMap<String, Long> statLocalDirectory(
      File localDirectory) {
    SortedMap<String, Long> localFiles = new TreeMap<String, Long>();
    if (!localDirectory.exists()) {
      return localFiles;
    }
    Stack<File> files = new Stack<File>();
    files.add(localDirectory);
    while (!files.isEmpty()) {
      File file = files.pop();
      if (file.isDirectory()) {
        files.addAll(Arrays.asList(file.listFiles()));
      } else {
        String localPath = file.getPath().substring(
            localDirectory.getPath().length());
        localFiles.put(localPath, file.lastModified());
      }
    }
    return localFiles;
  }

  SortedMap<String, String> fetchRemoteDirectories(
      String collecTorBaseUrl, String[] remoteDirectories) {
    SortedMap<String, String> fetchedDirectoryListings =
        new TreeMap<String, String>();
    for (String remoteDirectory : remoteDirectories) {
      String remoteDirectoryWithSlashAtBeginAndEnd =
          (remoteDirectory.startsWith("/") ? "" : "/") + remoteDirectory
          + (remoteDirectory.endsWith("/") ? "" : "/");
      String directoryUrl = collecTorBaseUrl
          + remoteDirectoryWithSlashAtBeginAndEnd;
      String directoryListing = this.fetchRemoteDirectory(directoryUrl);
      if (directoryListing.length() > 0) {
        fetchedDirectoryListings.put(
            remoteDirectoryWithSlashAtBeginAndEnd, directoryListing);
      }
    }
    return fetchedDirectoryListings;
  }

  String fetchRemoteDirectory(String url) {
    StringBuilder sb = new StringBuilder();
    try {
      URL u = new URL(url);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      huc.connect();
      int responseCode = huc.getResponseCode();
      if (responseCode == 200) {
        BufferedReader br = new BufferedReader(new InputStreamReader(
            huc.getInputStream()));
        String line;
        while ((line = br.readLine()) != null) {
          sb.append(line + "\n");
        }
        br.close();
      }
    } catch (IOException e) {
      e.printStackTrace();
      return "";
    }
    return sb.toString();
  }

  final Pattern DIRECTORY_LISTING_LINE_PATTERN =
      Pattern.compile(".* href=\"([^\"/]+)\"" /* filename */
      + ".*>(\\d{2}-\\w{3}-\\d{4} \\d{2}:\\d{2})\\s*<.*"); /* dateTime */

  SortedMap<String, Long> parseDirectoryListing(
      String remoteDirectory, String directoryListing) {
    SortedMap<String, Long> remoteFiles = new TreeMap<String, Long>();
    DateFormat dateTimeFormat = ParseHelper.getDateFormat(
        "dd-MMM-yyyy HH:mm");
    try {
      Scanner s = new Scanner(directoryListing);
      s.useDelimiter("\n");
      while (s.hasNext()) {
        String line = s.next();
        Matcher matcher = DIRECTORY_LISTING_LINE_PATTERN.matcher(line);
        if (matcher.matches()) {
          String filename = matcher.group(1);
          long lastModifiedMillis = dateTimeFormat.parse(
              matcher.group(2)).getTime();
          remoteFiles.put(remoteDirectory + filename, lastModifiedMillis);
        }
      }
      s.close();
    } catch (ParseException e) {
      e.printStackTrace();
      return null;
    }
    return remoteFiles;
  }

  void fetchRemoteFiles(String collecTorBaseUrl,
      SortedMap<String, Long> remoteFiles, long minLastModified,
      File localDirectory, SortedMap<String, Long> localFiles) {
    for (Map.Entry<String, Long> e : remoteFiles.entrySet()) {
      String filename = e.getKey();
      long lastModifiedMillis = e.getValue();
      if (lastModifiedMillis < minLastModified ||
          (localFiles.containsKey(filename) &&
          localFiles.get(filename) >= lastModifiedMillis)) {
        continue;
      }
      String url = collecTorBaseUrl + filename;
      File destinationFile = new File(localDirectory.getPath()
          + filename);
      this.fetchRemoteFile(url, destinationFile, lastModifiedMillis);
    }
  }

  void fetchRemoteFile(String url, File destinationFile,
      long lastModifiedMillis) {
    try {
      File destinationDirectory = destinationFile.getParentFile();
      destinationDirectory.mkdirs();
      File tempDestinationFile = new File(destinationDirectory, "."
          + destinationFile.getName());
      FileOutputStream fos = new FileOutputStream(tempDestinationFile);
      URL u = new URL(url);
      HttpURLConnection huc = (HttpURLConnection) u.openConnection();
      huc.setRequestMethod("GET");
      if (!url.endsWith(".xz")) {
        huc.addRequestProperty("Accept-Encoding", "gzip");
      }
      huc.connect();
      int responseCode = huc.getResponseCode();
      if (responseCode == 200) {
        InputStream is;
        if (huc.getContentEncoding() != null &&
            huc.getContentEncoding().equalsIgnoreCase("gzip")) {
          is = new GZIPInputStream(huc.getInputStream());
        } else {
          is = huc.getInputStream();
        }
        BufferedInputStream bis = new BufferedInputStream(is);
        int len;
        byte[] data = new byte[1024];
        while ((len = bis.read(data, 0, 1024)) >= 0) {
          fos.write(data, 0, len);
        }
        bis.close();
        fos.close();
        tempDestinationFile.renameTo(destinationFile);
        destinationFile.setLastModified(lastModifiedMillis);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  void deleteExtraneousLocalFiles(
      SortedSet<String> parsedDirectories,
      SortedMap<String, Long> remoteFiles, File localDirectory,
      SortedMap<String, Long> localFiles) {
    for (String localPath : localFiles.keySet()) {
      for (String remoteDirectory : parsedDirectories) {
        if (localPath.startsWith(remoteDirectory)) {
          if (!remoteFiles.containsKey(localPath)) {
            new File(localDirectory.getPath() + localPath).delete();
          }
        }
      }
    }
  }
}

