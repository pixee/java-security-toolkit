/** Export our package so that it can be used by other modules. */
open module io.github.pixee.security {
  exports io.github.pixee.security;
  exports io.github.pixee.security.jakarta;

  requires org.apache.commons.io;
  requires java.xml;
  requires java.desktop;
  requires java.base;
}
