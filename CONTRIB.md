A contributor's guide to how we develop metrics-lib 
===================================================

Dear contributor to metrics-lib, this text is an attempt to tell you how we do development for this fine library.  We highly encourage you to read it when making contributions to metrics-lib to make it easier for us to accept them.  But we also invite you to question these guidelines and make suggestions if you see room for improvement.


Purpose
-------

Before we go into the details of writing code, let's briefly talk about the purpose of metrics-lib.  Back in 2011, the reason for creating this library was to avoid rewriting the same code over and over that would handle data gathered in the Tor network.  metrics-lib is now being used in the major Java-based tools in the Tor metrics space, and it's being used by researchers to do one-off analyses of Tor network data.


Design overview
---------------

metrics-lib is not that big, so it shouldn't be difficult to go through the interfaces and classes to see what they are doing.  But to give you a general overview, here are some highlights:

 - We tried to separate interfaces from implementation classes as much as possible and put them into different packages.  As a rule of thumb, applications using metrics-lib should never need to import one of the implementation classes.

 - There are two types of classes: descriptor classes and classes that provide descriptor instances.  For the first type there's a class for each method to obtain descriptors, and for the second type there's a class for pretty much each kind of descriptor that is available in the Tor network.


Dependencies
------------

We tried to keep the number of dependencies as small as possible, and we tried to avoid adding any dependencies that wouldn't be available in common operating system distributions like Debian stable.  That doesn't mean that we're opposed to add any further dependencies, but we need to keep in mind that any user of our library will have to add those dependencies, too.

metrics-lib currently has the following dependencies to compile:

 - Apache Commons Compression 1.4.1 (https://commons.apache.org/proper/commons-compress/)
   https://archive.apache.org/dist/commons/compress/binaries/

 - JUnit 4.10 (http://junit.org/)
   https://search.maven.org/remotecontent?filepath=junit/junit/4.10/junit-4.10.jar

Code style
----------

We're using a code style that is not really formally defined but that roughly follows these rules:

 - We avoid tabs and favor 2 spaces where other people would use a tab.
 - We break lines after at most 74 characters and indent new lines with 4 spaces.
 - Every public interface or method should have a javadoc comment, which should be a full sentence.  We failed to turn these comments into JavaDoc comments, but we should fix that at some point.

There's probably more to say about code style, but please take a look at the existing code and try to write new code as similar as possible.


Tests
-----

metrics-lib is still rather light on unit tests, but that shouldn't prevent us from writing tests for new code.  Test classes go into a separate source directory and use the same package structure as the class they're supposed to test.


Deprecating features
--------------------

We have to assume that applications don't update their metrics-lib version very often.  This is related to the lack of a release process so far.  If we want to remove a feature we'll have to deprecate it and basically keep it working for at least another year.


Change log
----------

We didn't have a change log for a long time, but we should totally have one if we want to put out releases.  Here we're going to describe what deserves a change log entry and whether those changes are major, medium, or minor:

 - Bug fixes obviously need a change log entry, but it depends on the bug whether it should be listed as major or medium change.

 - Enhancements that extend the API are also worth noting in the change log, though their importance would most likely be medium.

 - All enhancements must be backwards-compatible, so whenever we want to switch to a different interface we'll have to deprecate the existing interface and at the same time provide a new one that applications should use instead.  Deprecating a feature would be a medium change that should be mentioned in the change log.

 - Enhancements that make the implementation more efficient or that refactor some internal code might also be worth noting in the change log, but very likely as medium enhancements.  An exception would be ground-breaking performance improvements that most application developers would care about, which would be major enhancements.

 - Whenever we add a new dependency, that's clearly a major change that needs to be written into the change log, because applications will have to add this dependency, too.

 - Removing an existing dependency is also worth mentioning in the change log, though that's rather a medium change that doesn't force applications to act that quickly.

 - Any simple code cleanups, new tests, changes to documentation like this file, etc. only require a summary change log entry and will lead to a minor version change.


Releases
--------

As mentioned before we didn't put out releases for far too long.  But we're about to change that.  As a rule of thumb, we should put out a new release of metrics-lib soon after making a major change as listed under "Change log" above.  If we're planning to make more changes soon after, let's wait for them and make a release with everything.  But we shouldn't let a major change sit in an unreleased metrics-lib for more than, say, two weeks.  In contrast to that, medium changes can stay unreleased for longer, though they don't have to if we want to use them in an application sooner. Minor changes can be collected and usually will be released with changes on higher stages, but when necessary they can be released earlier.

Regarding version numbers, we'll start with 1.0.0 and bump to 1.0.1, 1.1.0, 1.2.0, etc. for each backwards-compatible change.  When we remove a previously deprecated feature, making a backwards-incompatible change, we'll bump to 2.0.0.


Packages
--------

There are no metrics-lib packages yet, but we should aim for providing packages for at least Debian stable, either official or unofficial.


Closing words
-------------

Dear contributor, now that you made it to the end of this guide, please be reminded that these are just guidelines that shall make it easier for us to work on metrics-lib.  But we're making these rules ourselves, and that "we" includes you.  Please suggest any changes to this guide and help us make it better.  Thanks!

