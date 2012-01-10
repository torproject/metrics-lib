/* Copyright 2011, 2012 The Tor Project
 * See LICENSE for licensing information */
package org.torproject.descriptor.impl;

import java.util.LinkedList;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.Queue;

/* Provide an iterator for a queue of objects and block when there are
 * currently no objects in the queue.  Allow the producer to signal that
 * there won't be further objects and unblock any waiting consumers. */
public class BlockingIteratorImpl<T> implements Iterator<T> {

  /* Queue containing produced elemnts waiting for consumers. */
  private Queue<T> queue = new LinkedList<T>();

  /* Restrict object construction to the impl package. */
  protected BlockingIteratorImpl() {
  }

  /* Add an object to the queue. */
  protected synchronized void add(T object) {
    if (this.outOfDescriptors) {
      throw new IllegalStateException("Internal error: Adding results to "
          + "descriptor queue not allowed after sending end-of-stream "
          + "object.");
    }
    this.queue.offer(object);
    notifyAll();
  }

  /* Signalize that there won't be any further objects to be enqueued. */
  private boolean outOfDescriptors = false;
  protected synchronized void setOutOfDescriptors() {
    if (this.outOfDescriptors) {
      throw new IllegalStateException("Internal error: Sending "
          + "end-of-stream object only permitted once.");
    }
    this.outOfDescriptors = true;
    notifyAll();
  }

  /* Return whether there are more objects.  Block if there are currently
   * no objects, but the producer hasn't signalized that there won't be
   * further objects. */
  public synchronized boolean hasNext() {
    while (!this.outOfDescriptors && this.queue.isEmpty()) {
      try {
        wait();
      } catch (InterruptedException e) {
      }
    }
    return this.queue.peek() != null;
  }

  /* Return the next object in the queue or throw an exception when there
   * are no further objects.  Block if there are currently no objects, but
   * the producer hasn't signalized that there won't be further
   * objects. */
  public synchronized T next() {
    while (!this.outOfDescriptors && this.queue.isEmpty()) {
      try {
        wait();
      } catch (InterruptedException e) {
      }
    }
    if (this.queue.peek() == null) {
      throw new NoSuchElementException();
    }
    return this.queue.remove();
  }

  /* Don't support explicitly removing objects.  They are removed
   * anyway. */
  public void remove() {
    throw new UnsupportedOperationException();
  }
}

