package io.github.pixee.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.naming.Context;
import javax.naming.NamingException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

final class JNDITest {

    private Context context;
    private final Object NAMED_OBJECT = new Object();
    private final Object JAVA_OBJECT = new Object();
    private final Object LDAP_OBJECT = new Object();
    private final Object RMI_OBJECT = new Object();

    @BeforeEach
    void setup() throws NamingException {
        context = mock(Context.class);
        when(context.lookup("simple_name")).thenReturn(NAMED_OBJECT);
        when(context.lookup("java:comp/env")).thenReturn(JAVA_OBJECT);
        when(context.lookup("ldap://localhost:1389/ou=system")).thenReturn(LDAP_OBJECT);
        when(context.lookup("rmi://localhost:1099/evil")).thenReturn(RMI_OBJECT);
    }

    @Test
    void it_limits_resources_by_name() throws NamingException {
        JNDI.LimitedContext limitedContext = JNDI.limitedContextByResourceName(context, J8ApiBridge.setOf("simple_name"));
        assertThat(limitedContext.lookup("simple_name"), is(NAMED_OBJECT));
        assertThrows(SecurityException.class, () -> limitedContext.lookup("anything_else"));
        verify(context, times(1)).lookup(anyString());
    }

    @Test
    void it_limits_resources_by_protocol() throws NamingException {
        JNDI.LimitedContext onlyJavaContext = JNDI.limitedContextByProtocol(context, J8ApiBridge.setOf(UrlProtocol.JAVA));
        assertThat(onlyJavaContext.lookup("java:comp/env"), is(JAVA_OBJECT));
        assertThrows(SecurityException.class, () -> onlyJavaContext.lookup("ldap://localhost:1389/ou=system"));
        assertThrows(SecurityException.class, () -> onlyJavaContext.lookup("rmi://localhost:1099/evil"));

        JNDI.LimitedContext onlyLdapContext = JNDI.limitedContextByProtocol(context, J8ApiBridge.setOf(UrlProtocol.LDAP));
        assertThat(onlyLdapContext.lookup("ldap://localhost:1389/ou=system"), is(LDAP_OBJECT));
        assertThrows(SecurityException.class, () -> onlyLdapContext.lookup("java:comp/env"));
        assertThrows(SecurityException.class, () -> onlyLdapContext.lookup("rmi://localhost:1099/evil"));

        JNDI.LimitedContext onlyLdapAndJavaContext = JNDI.limitedContextByProtocol(context, J8ApiBridge.setOf(UrlProtocol.JAVA, UrlProtocol.LDAP));
        assertThat(onlyLdapAndJavaContext.lookup("ldap://localhost:1389/ou=system"), is(LDAP_OBJECT));
        assertThat(onlyLdapAndJavaContext.lookup("java:comp/env"), is(JAVA_OBJECT));
        assertThrows(SecurityException.class, () -> onlyLdapAndJavaContext.lookup("rmi://localhost:1099/evil"));
    }

    @Test
    void default_limits_rmi_and_ldap() throws NamingException {
        JNDI.LimitedContext defaultLimitedContext = JNDI.limitedContext(context);
        assertThat(defaultLimitedContext.lookup("java:comp/env"), is(JAVA_OBJECT));
        assertThrows(SecurityException.class, () -> defaultLimitedContext.lookup("rmi://localhost:1099/evil"));
        assertThrows(SecurityException.class, () -> defaultLimitedContext.lookup("ldap://localhost:1389/ou=system"));
    }

}