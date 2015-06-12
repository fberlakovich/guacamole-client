/*
 * Copyright (C) 2015 Felix Berlakovich
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package net.sourceforge.guacamole.net.auth.ldap;

import net.sourceforge.guacamole.net.auth.ldap.properties.ADGuacamoleProperties;
import org.glyptodon.guacamole.GuacamoleException;
import org.glyptodon.guacamole.GuacamoleServerException;
import org.glyptodon.guacamole.environment.Environment;
import org.glyptodon.guacamole.environment.LocalEnvironment;
import org.glyptodon.guacamole.net.auth.Credentials;
import org.glyptodon.guacamole.net.auth.simple.SimpleAuthenticationProvider;
import org.glyptodon.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import java.util.Hashtable;
import java.util.Map;
import java.util.TreeMap;

/**
 * Allows users to be authenticated against an Active Directory. Each user may have
 * any number of authorized configurations. Authorized configurations may be
 * shared.
 *
 * @author Felix Berlakovich
 */
public class ADAuthenticationProvider extends SimpleAuthenticationProvider {

    /**
     * Logger for this class.
     */
    private Logger logger = LoggerFactory.getLogger(ADAuthenticationProvider.class);

    /**
     * Guacamole server environment.
     */
    private final Environment environment;

    /**
     * Creates a new ADAuthenticationProvider that authenticates users
     * against an Active Directory.
     *
     * @throws GuacamoleException If a required property is missing, or an error occurs while parsing
     *                            a property.
     */
    public ADAuthenticationProvider() throws GuacamoleException {
        environment = new LocalEnvironment();
    }


    @Override
    public Map<String, GuacamoleConfiguration> getAuthorizedConfigurations(Credentials credentials) throws GuacamoleException {

        // Require username
        if (credentials.getUsername() == null) {
            logger.debug("Anonymous bind is not currently allowed by the AD authentication provider. Please specify a username.");
            return null;
        }

        // Require password, and do not allow anonymous binding
        if (credentials.getPassword() == null
                || credentials.getPassword().length() == 0) {
            logger.debug("Anonymous bind is not currently allowed by the AD authentication provider. Please specify a password.");
            return null;
        }

        String hostname = environment.getRequiredProperty(ADGuacamoleProperties.LDAP_HOSTNAME);
        String domainName = environment.getRequiredProperty(ADGuacamoleProperties.LDAP_DOMAIN);

        // If no hostname is not supplied fall back to the domain name and LDAP referrals
        if (hostname == null || hostname.length() == 0) {
            logger.debug("No hostname was supplied, falling back to using the domain name and LDAP referrals");
            hostname = domainName;
        }

        // Get config base DN
        String configBaseDn = environment.getRequiredProperty(
                ADGuacamoleProperties.LDAP_CONFIG_BASE_DN
        );

        // Get user base DN
        String userBaseDn = environment.getRequiredProperty(
                ADGuacamoleProperties.LDAP_USER_BASE_DN
        );

        Hashtable<String, String> props = new Hashtable<String, String>();
        props.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");

        String principalName;
        if (credentials.getUsername().indexOf('@') != -1) {
            principalName = credentials.getUsername();
        } else {
            principalName = LDAPUtilities.escapeDN(credentials.getUsername()) + "@" + domainName;
        }

        logger.debug("Using principal name {}", principalName);

        props.put(Context.SECURITY_PRINCIPAL, principalName);
        props.put(Context.SECURITY_CREDENTIALS, credentials.getPassword());

        props.put(Context.PROVIDER_URL, "ldap://" + hostname + ":" +
                        environment.getRequiredProperty(ADGuacamoleProperties.LDAP_PORT));

        DirContext context;

        Map<String, GuacamoleConfiguration> configs;
        try {
            context = new InitialLdapContext(props, null);

            // locate this user's record
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            // Retrieve the user object
            NamingEnumeration<SearchResult> results = context.search(userBaseDn,
                    "(&(userPrincipalName=" + principalName + ")(objectClass=user))", controls);
            if (!results.hasMore()) {
                throw new GuacamoleServerException("Error while getting information for user " + credentials.getUsername());
            }
            SearchResult result = results.next();
            String userDn = result.getAttributes().get("distinguishedname").get().toString();

            logger.trace("User with principal {} has DN {}", principalName, userDn);

            // Retrieve the configurations where this user is member
            String searchFilter = "(&(objectClass=guacConfigGroup)(member=" + LDAPUtilities.escapeLDAPSearchFilter(userDn) + "))";
            NamingEnumeration<SearchResult> configResults = context.search(configBaseDn, searchFilter, controls);

            configs = parseConfigs(configResults);

        } catch (NamingException e) {
            throw new GuacamoleServerException("Error while connecting to the LDAP Server", e);
        }

        return configs;
    }

    private Map<String, GuacamoleConfiguration> parseConfigs(NamingEnumeration<SearchResult> configResults)
            throws NamingException, GuacamoleException {
        Map<String, GuacamoleConfiguration> configs = new TreeMap<String, GuacamoleConfiguration>();
        while (configResults.hasMore()) {
            SearchResult configEntry = configResults.next();
            Attributes attributes = configEntry.getAttributes();
            GuacamoleConfiguration config = new GuacamoleConfiguration();

            Attribute cn = attributes.get("cn");
            if (cn == null)
                throw new GuacamoleException("guacConfigGroup without cn");

            Attribute protocol = attributes.get("guacConfigProtocol");
            if (protocol == null)
                throw new GuacamoleException("guacConfigGroup without protocol");

            config.setProtocol(protocol.get().toString());

            Attribute parameter = attributes.get("guacConfigParameter");
            if (parameter != null) {
                NamingEnumeration<?> values = parameter.getAll();
                while (values.hasMore()) {
                    String parameterValue = values.next().toString();

                    // Parse the parameter
                    int equals = parameterValue.indexOf('=');
                    if (equals != -1) {
                        String name = parameterValue.substring(0, equals);
                        String value = parameterValue.substring(equals + 1);
                        config.setParameter(name, value);
                    }
                }
            }

            configs.put(cn.get().toString(), config);
        }
        return configs;
    }
}

