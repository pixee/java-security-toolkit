package io.pixee.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import java.util.List;
import java.util.Objects;
import org.apache.commons.io.serialization.ValidatingObjectInputStream;

/**
 * This type exposes helper methods that will help defend against deserialization attacks.
 *
 * <p>For more information on deserialization:
 * https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
 */
public final class Deserialization {

  private Deserialization() {}

  /**
   * This method returns an {@link ObjectInputFilter} for use in {@link
   * java.io.ObjectInputStream#setObjectInputFilter(ObjectInputFilter)} to protect against
   * deserialization code execution attacks. This method is meant for Java 9+ apps since it relies
   * on methods introduced in that version.
   */
  public static ObjectInputFilter hardenedObjectFilter() {
    return filter;
  }

  /**
   * This method attempts to install an {@link ObjectInputFilter} if one doesn't exist in order to
   * protect against deserialization code execution attacks. This is meant for Java 9+ apps since it
   * relies on methods introduced in that version.
   *
   * <p>Note: code weavers can't weave this code directly into arbitrary code because it forces you
   * to choose what to do in the try-catch block. An empty catch block may cause checkstyle
   * violations, and will look more disruptive.
   */
  public static void enableObjectFilterIfUnprotected(final ObjectInputStream ois) {
    var objectInputFilter = ois.getObjectInputFilter();
    if (objectInputFilter == null) {
      try {
        ois.setObjectInputFilter(filter);
      } catch (Exception e) {
        /*
         * This is expected when the SecurityManager has an opinion about this, or maybe another thread has installed an
         * ObjectInputFilter, or something else unexpected.
         */
      }
    }
  }

  /**
   * This method returns an {@link ObjectInputFilter} for use in {@link
   * java.io.ObjectInputStream#setObjectInputFilter(ObjectInputFilter)} to protect against
   * deserialization code execution attacks. This method is meant for Java 9+ apps since it relies
   * on methods introduced in that version.
   *
   * <p>This method attempts to combine the default protections of this utility with an existing
   * filter in the app code.
   *
   * @param existingFilter the existing filter for the call about to take place, so we can work in
   *     tandem with it
   */
  public static ObjectInputFilter createCombinedHardenedObjectFilter(
      final ObjectInputFilter existingFilter) {
    if (existingFilter == null) {
      return filter;
    }
    return new CombinedObjectInputFilter(existingFilter);
  }

  static class CombinedObjectInputFilter implements ObjectInputFilter {
    private final ObjectInputFilter originalFilter;

    private CombinedObjectInputFilter(final ObjectInputFilter originalFilter) {
      this.originalFilter = Objects.requireNonNull(originalFilter);
    }

    @Override
    public Status checkInput(final FilterInfo filterInfo) {
      if (Status.REJECTED.equals(filter.checkInput(filterInfo))) {
        return Status.REJECTED;
      }
      return originalFilter.checkInput(filterInfo);
    }
  }

  /**
   * This method returns a wrapped {@link ObjectInputStream} that protects against deserialization
   * code execution attacks. This method can be used in Java 8 and previous.
   *
   * @param ois the stream to wrap and harden
   */
  public static ObjectInputStream createSafeObjectInputStream(final InputStream ois)
      throws IOException {
    try {
      final ValidatingObjectInputStream is = new ValidatingObjectInputStream(ois);
      for (String gadget : gadgets) {
        is.reject("*" + gadget);
      }
      return is;
    } catch (IOException e) {
      // ignored
    }

    // if for some reason we can't replace it, we'll pass it back as it was given
    return new ObjectInputStream(ois);
  }

  private static final List<String> gadgets =
      List.of(
          " org.apache.commons.beanutils.BeanComparator".substring(1),
          " org.apache.commons.collections.functors.ChainedTransformer".substring(1),
          " org.apache.commons.collections.functors.ConstantTransformer".substring(1),
          " org.apache.commons.collections.functors.InstantiateTransformer".substring(1),
          " org.apache.commons.collections.functors.InvokerTransformer".substring(1),
          " org.apache.commons.collections4.functors.InstantiateTransformer".substring(1),
          " org.apache.commons.collections4.functors.InvokerTransformer".substring(1),
          " org.apache.commons.fileupload.disk.DiskFileItem".substring(1),
          " org.apache.myfaces.view.facelets.el.ValueExpressionMethodExpression".substring(1),
          " org.apache.wicket.util.upload.DiskFileItem".substring(1),
          " org.apache.xalan.internal.xsltc.trax.TemplatesImpl".substring(1),
          " org.apache.xalan.xsltc.trax.TemplatesImpl".substring(1),
          "bsh.Interpreter",
          "bsh.XThis",
          "ch.qos.logback.core.db.DriverManagerConnectionSource",
          "clojure.inspector.proxy$javax.swing.table.AbstractTableModel$ff19274a",
          "coldfusion.syndication.FeedDateParser",
          "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
          "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
          "com.mchange.v2.c3p0.impl.PoolBackedDataSourceBase",
          "com.mchange.v2.naming.ReferenceIndirector$ReferenceSerialized",
          "com.sun.jna.Function",
          "com.sun.jna.Memory",
          "com.sun.jndi.rmi.registry.BindingEnumeration",
          "com.sun.jndi.toolkit.dir.LazySearchEnumerationImpl",
          "com.sun.medialib.codec.jpeg.Encoder",
          "com.sun.medialib.codec.png.Decoder",
          "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
          "com.sun.org.apache.xalan.internal.xsltc.trax.TrAXFilter",
          "com.sun.rowset.JdbcRowSetImpl",
          "com.sun.rowset.JdbcRowSetImpl$",
          "com.sun.syndication.feed.impl.ObjectBean",
          "com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data",
          "com.xuggle.ferry.AtomicInteger",
          "groovy.util.Expando",
          "java.lang.ProcessBuilder",
          "java.net.PlainDatagramSocketImpl",
          "java.rmi.registry.Registry$",
          "java.rmi.server.ObjID$",
          "java.rmi.server.RemoteObjectInvocationHandler$",
          "java.rmi.server.UnicastRemoteObject",
          "java.util.ServiceLoader$LazyIterator",
          "java.util.logging.FileHandler",
          "javax.imageio.ImageIO$ContainsFilter",
          "javax.management.BadAttributeValueExpException",
          "javax.xml.transform.Templates$",
          "mozilla.javascript.ScriptableObject$GetterSlot",
          "mozilla.javascript.ScriptableObject$RelinkedSlot",
          "mozilla.javascript.ScriptableObject$Slot",
          "mozilla.javascript.internal.NativeError",
          "net.sf.json.JSONObject$",
          "org.apache.myfaces.el.CompositeELResolver$",
          "org.apache.myfaces.el.unified.FacesELContext$",
          "org.codehaus.groovy.runtime.ConvertedClosure",
          "org.codehaus.groovy.runtime.MethodClosure",
          "org.hibernate.engine.spi.TypedValue$",
          "org.hibernate.tuple.component.AbstractComponentTuplizer$",
          "org.hibernate.tuple.component.PojoComponentTuplizer$",
          "org.hibernate.type.AbstractType$",
          "org.hibernate.type.ComponentType$",
          "org.hibernate.type.Type$",
          "org.jboss.interceptor.builder.InterceptionModelBuilder$",
          "org.jboss.interceptor.builder.MethodReference$",
          "org.jboss.interceptor.proxy.DefaultInvocationContextFactory$",
          "org.jboss.interceptor.proxy.InterceptorMethodHandler$",
          "org.jboss.interceptor.reader.ClassMetadataInterceptorReference$",
          "org.jboss.interceptor.reader.DefaultMethodMetadata$",
          "org.jboss.interceptor.reader.ReflectiveClassMetadata$",
          "org.jboss.interceptor.reader.SimpleInterceptorMetadata$",
          "org.jboss.interceptor.spi.instance.InterceptorInstantiator$",
          "org.jboss.interceptor.spi.metadata.InterceptorReference$",
          "org.jboss.interceptor.spi.metadata.MethodMetadata$",
          "org.jboss.interceptor.spi.model.InterceptionModel$",
          "org.jboss.interceptor.spi.model.InterceptionType$",
          "org.jboss.weld.interceptor.builder.InterceptionModelBuilder$",
          "org.jboss.weld.interceptor.builder.MethodReference$",
          "org.jboss.weld.interceptor.proxy.DefaultInvocationContextFactory$",
          "org.jboss.weld.interceptor.proxy.InterceptorMethodHandler$",
          "org.jboss.weld.interceptor.reader.ClassMetadataInterceptorReference$",
          "org.jboss.weld.interceptor.reader.DefaultMethodMetadata$",
          "org.jboss.weld.interceptor.reader.ReflectiveClassMetadata$",
          "org.jboss.weld.interceptor.reader.SimpleInterceptorMetadata$",
          "org.jboss.weld.interceptor.spi.instance.InterceptorInstantiator$",
          "org.jboss.weld.interceptor.spi.metadata.InterceptorReference$",
          "org.jboss.weld.interceptor.spi.metadata.MethodMetadata$",
          "org.jboss.weld.interceptor.spi.model.InterceptionModel$",
          "org.jboss.weld.interceptor.spi.model.InterceptionType$",
          "org.jboss.weld.interceptor.reader.DefaultMethodMetadata",
          "org.jpedal.io.ObjectStore",
          "org.python.core.PyBytecode",
          "org.python.core.PyBytecode$",
          "org.python.core.PyFunction",
          "org.python.core.PyFunction$",
          "org.python.core.PyObject$",
          "org.springframework.aop.framework.AdvisedSupport",
          "org.springframework.beans.factory.ObjectFactory",
          "org.springframework.beans.factory.ObjectFactory",
          "org.springframework.beans.factory.config.PropertyPathFactoryBean",
          "sun.rmi.server.UnicastRef",
          "sun.rmi.transport.DGCClient$EndpointEntry");

  private static final ObjectInputFilter filter =
      ObjectInputFilter.Config.createFilter("!" + String.join(";!", gadgets));
}
