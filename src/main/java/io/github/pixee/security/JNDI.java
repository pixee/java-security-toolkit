package io.github.pixee.security;

import javax.naming.Context;
import javax.naming.NamingException;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Offers utilities to defend against JNDI attacks by controlling allowed resources. */
public final class JNDI {

    private JNDI() {}

    /**
     * Looks up a resource in the context, only allowing resources non-URL-based resources and "java:" resources.
     */
    public static LimitedContext limitedContext(final Context context) {
        return new ProtocolLimitedContext(context, J8ApiBridge.setOf(UrlProtocol.JAVA));
    }

    /**
     * Looks up a resource in the context, only allowing resources from the specified protocols.
     */
    public static LimitedContext limitedContextByProtocol(final Context context, final Set<UrlProtocol> allowedProtocols) {
        return new ProtocolLimitedContext(context, allowedProtocols);
    }

    /**
     * Looks up a resource in the context, only allowing resources with the given names.
     */
    public static LimitedContext limitedContextByResourceName(final Context context, final Set<String> allowedResourceNames) {
        return new NameLimitedContext(context, allowedResourceNames);
    }

    /** A lookalike method for {@link Context} that allows sandboxing resolution. */
    public interface LimitedContext {
        /**
         * Looks up a resource in the context, but only allows resources that are in the allowed set.
         *
         * @param resource the resource to look up
         * @return the object bound to the resource
         * @throws NamingException if the resource is not allowed or if the lookup fails as per {@link Context#lookup(String)}
         */
        Object lookup(final String resource) throws NamingException;
    }

    /** A context which limits protocols. */
    private static class ProtocolLimitedContext implements LimitedContext {
        private final Context context;
        private final Set<UrlProtocol> allowedProtocols;

        private ProtocolLimitedContext(final Context context, final Set<UrlProtocol> allowedProtocols) {
            this.context = Objects.requireNonNull(context);
            this.allowedProtocols = Objects.requireNonNull(allowedProtocols);
        }

        @Override
        public Object lookup(final String resource) throws NamingException {
            Set<String> allowedProtocolPrefixes = allowedProtocols.stream().map(UrlProtocol::getKey).map(p -> p + ":").collect(Collectors.toSet());
            String canonicalResource = resource.toLowerCase().trim();
            if (allowedProtocolPrefixes.stream().anyMatch(canonicalResource::startsWith)) {
                return context.lookup(resource);
            }
            throw new SecurityException("Unexpected JNDI resource protocol: " + resource);
        }
    }

    /** A context which only allows pre-defined resource names. */
    private static class NameLimitedContext implements LimitedContext {
        private final Context context;
        private final Set<String> allowedResourceNames;

        private NameLimitedContext(final Context context, final Set<String> allowedResourceNames) {
            this.context = Objects.requireNonNull(context);
            this.allowedResourceNames = Objects.requireNonNull(allowedResourceNames);
        }
        @Override
        public Object lookup(final String resource) throws NamingException {
            if(allowedResourceNames.contains(resource)) {
                return context.lookup(resource);
            }
            throw new SecurityException("Unexpected JNDI resource name: " + resource);
        }
    }
}