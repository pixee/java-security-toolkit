package io.github.pixee.security;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * This type is only intended to hold a list of types that we don't want to deserialize because they
 * pose a security risk.
 */
public final class UnwantedTypes {

  private UnwantedTypes() {}

  /**
   * Return a {@link List} of class names and parts of class names that represent unwanted types.
   * These types are generally undesirable to deserialize or introspect/execute from unknown
   * sources. This list represents publicly known types but future research could uncover new types
   * that are dangerous.
   *
   * <p>To use this list effectively, you should see if any of these tokens are in the type name you
   * are considering interacting with. For example, this code is wrong and dangerous:
   *
   * <pre>{@code
   * String className = userRequest.getType();
   * if(UnwantedTypes.allTokens().contains(className)) { // wrong!
   *   doSomethingWith(className);
   * }
   * }</pre>
   *
   * While this code is
   *
   * <pre>{@code
   * String className = userRequest.getType();
   * if(UnwantedTypes.allTokens().noneMatch(c -> className.contains(c))) { // right
   *   doSomethingWith(className);
   * }
   * }</pre>
   *
   * If you just want to check if a class name is potentially unsafe, use {@link
   * #isUnwanted(String)} instead.
   *
   * @return a {@link List} of dangerous types to avoid deserializing
   */
  public static List<String> dangerousClassNameTokens() {
    return combinedGadgetTokens;
  }

  /**
   * Return true if the given class name is a known unwanted type. Note that this will return true
   * even for classes that have been shaded into another package.
   *
   * @param className a fully qualified class name to check
   * @return true if the given class name is a known unwanted type, false otherwise
   */
  public static boolean isUnwanted(final String className) {
    for (String gadgetToken : dangerousClassNameTokens()) {
      if (className.contains(gadgetToken)) {
        return true;
      }
    }
    return false;
  }

  /** A list of types known to be involved in deserialization and remote code execution attacks. */
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
          "com.sun.syndication.feed.impl.ObjectBean",
          "com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data",
          "com.xuggle.ferry.AtomicInteger",
          "groovy.util.Expando",
          "java.lang.ProcessBuilder",
          "java.net.PlainDatagramSocketImpl",
          "java.rmi.server.UnicastRemoteObject",
          "java.util.ServiceLoader$LazyIterator",
          "java.util.logging.FileHandler",
          "javax.imageio.ImageIO$ContainsFilter",
          "javax.management.BadAttributeValueExpException",
          "mozilla.javascript.ScriptableObject$GetterSlot",
          "mozilla.javascript.ScriptableObject$RelinkedSlot",
          "mozilla.javascript.ScriptableObject$Slot",
          "mozilla.javascript.internal.NativeError",
          "org.codehaus.groovy.runtime.ConvertedClosure",
          "org.codehaus.groovy.runtime.MethodClosure",
          "org.jboss.weld.interceptor.reader.DefaultMethodMetadata",
          "org.jpedal.io.ObjectStore",
          "org.python.core.PyBytecode",
          "org.python.core.PyFunction",
          "org.springframework.aop.framework.AdvisedSupport",
          "org.springframework.beans.factory.ObjectFactory",
          "org.springframework.beans.factory.ObjectFactory",
          "org.springframework.beans.factory.config.PropertyPathFactoryBean",
          "sun.rmi.server.UnicastRef",
          "sun.rmi.transport.DGCClient$EndpointEntry");

  /**
   * A list of class name common roots that have been known to be involved in deserialization and
   * remote code execution attacks.
   */
  private static final List<String> gadgetPrefixes =
      List.of(
          "com.sun.rowset.JdbcRowSetImpl$",
          "java.rmi.registry.Registry$",
          "java.rmi.server.ObjID$",
          "java.rmi.server.RemoteObjectInvocationHandler$",
          "javax.xml.transform.Templates$",
          "net.sf.json.JSONObject$",
          "org.apache.myfaces.el.CompositeELResolver$",
          "org.apache.myfaces.el.unified.FacesELContext$",
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
          "org.python.core.PyBytecode$",
          "org.python.core.PyFunction$",
          "org.python.core.PyObject$");

  private static final List<String> combinedGadgetTokens =
      Stream.concat(gadgets.stream(), gadgetPrefixes.stream()).collect(Collectors.toList());
}
