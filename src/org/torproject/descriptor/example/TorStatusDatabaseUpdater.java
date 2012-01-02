/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.example;

import java.io.File;
import java.util.Iterator;
import org.torproject.descriptor.Descriptor;
import org.torproject.descriptor.DescriptorFile;
import org.torproject.descriptor.DescriptorSourceFactory;
import org.torproject.descriptor.RelayDescriptorReader;
import org.torproject.descriptor.RelayNetworkStatusConsensus;
import org.torproject.descriptor.RelayNetworkStatusVote;

/* This is a non-functional (though syntactically correct) example for how
 * a TorStatus application could use the DescripTor API to read the cached
 * descriptors from a local Tor data directory and update its database.
 * This class will go away once a real TorStatus application uses this
 * API. */
public class TorStatusDatabaseUpdater {
  public static void main(String[] args) {

    /* Create an instance of the descriptor reader that implements the
     * logic to index and parse descriptor files from a local directory,
     * including the logic to ignore files that have been parsed in a
     * previous run. */
    RelayDescriptorReader reader =
        DescriptorSourceFactory.createRelayDescriptorReader();

    /* Tell the reader where to find relay descriptor files to parse.  In
     * this case it's a Tor data directory with cached descriptor
     * files. */
    reader.addDirectory(new File("tor-data-dir"));

    /* Exclude cached descriptor files that haven't changed since we last
     * ran this application.  This may save some execution time.  The
     * application needs to store the information when files were last
     * modified, because the API is supposed to be stateless. */
    reader.setExcludeFile(new File("tor-data-dir/cached-descriptors"),
        1234567890000L);

    /* Read all descriptors in the given directory and import them into
     * the database.  Also go through the list of parsed files and store
     * their last modification times, so that we can exclude them the next
     * time if they haven't changed. */
    Iterator<DescriptorFile> descriptorFiles = reader.readDescriptors();
    while (descriptorFiles.hasNext()) {
      DescriptorFile descriptorFile = descriptorFiles.next();
      for (Descriptor readDescriptor : descriptorFile.getDescriptors()) {
        /* Do something with the parsed descriptor. */
      }
      String fileName = descriptorFile.getFile().getName();
      long lastModified = descriptorFile.getLastModified();
      /* Do something with the file name and last modification time. */
    }
  }
}

