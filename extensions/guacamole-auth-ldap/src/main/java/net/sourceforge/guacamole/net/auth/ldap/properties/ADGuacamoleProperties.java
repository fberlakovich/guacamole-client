package net.sourceforge.guacamole.net.auth.ldap.properties;

import org.glyptodon.guacamole.properties.IntegerGuacamoleProperty;
import org.glyptodon.guacamole.properties.StringGuacamoleProperty;

/**
 * Provides properties required for use of the Active Directory authentication provider.
 * These properties will be read from guacamole.properties when the AD
 * authentication provider is used.
 *
 * @author Felix Berlakovich
 */
public class ADGuacamoleProperties {


    /**
     * This class should not be instantiated.
     */
    private ADGuacamoleProperties() {}

    /**
     * The base DN to search for Guacamole configurations.
     */
    public static final StringGuacamoleProperty LDAP_CONFIG_BASE_DN = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-config-base-dn"; }

    };

    /**
     * The base DN of users. All users must be direct children of this DN
     */
    public static final StringGuacamoleProperty LDAP_USER_BASE_DN = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-user-base-dn"; }

    };

    /**
     * The port on the LDAP server to connect to when authenticating users.
     */
    public static final IntegerGuacamoleProperty LDAP_PORT = new IntegerGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-port"; }

    };

    /**
     * The hostname of the LDAP server to connect to when authenticating users.
     */
    public static final StringGuacamoleProperty LDAP_HOSTNAME = new StringGuacamoleProperty() {

        @Override
        public String getName() { return "ldap-hostname"; }

    };

    /**
     * The domain name of the Active Directory domain
     */
    public static final StringGuacamoleProperty LDAP_DOMAIN = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "ad-domain";
        }
    };

}
