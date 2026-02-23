// Service Renderers Configuration
// Config-driven architecture for rendering service-specific enrichment data

// ==================== Service Configuration ====================

const SERVICE_RENDERERS = {
    smtp: {
        title: 'SMTP',
        match: (name) => ['smtp', 'smtps', 'submission'].includes(name),
        fields: [
            { key: 'banner', type: 'row', label: 'Banner', long: true },
            { key: 'hostname', type: 'inline', label: 'Hostname' },
            { key: 'supports_tls', type: 'bool', label: 'STARTTLS' },
            { key: 'supports_auth', type: 'bool', label: 'Auth' },
            { key: 'auth_methods', type: 'tags', label: 'Auth Methods', tagClass: 'info' },
            { key: 'commands', type: 'tags', label: 'EHLO Commands' }
        ]
    },

    ftp: {
        title: 'FTP',
        match: (name) => ['ftp', 'ftps'].includes(name),
        fields: [
            { key: 'banner', type: 'row', label: 'Banner', long: true },
            {
                key: 'welcome_message',
                type: 'row',
                label: 'Welcome',
                long: true,
                condition: (data) => data?.welcome_message && data.welcome_message !== data.banner
            },
            { key: 'anonymous_login', type: 'bool', label: 'Anonymous Login' },
            { key: 'supports_tls', type: 'bool', label: 'TLS Support' },
            { key: 'supports_passive', type: 'bool', label: 'Passive Mode' },
            { key: 'features', type: 'tags', label: 'Features', parser: 'array' }
        ]
    },

    imap: {
        title: (data, serviceName) => data?.protocol || serviceName.toUpperCase(),
        match: (name) => ['imap', 'imaps', 'pop3', 'pop3s'].includes(name),
        fields: [
            { key: 'banner', type: 'row', label: 'Banner', long: true },
            { key: 'capabilities', type: 'tags', label: 'Capabilities' }
        ]
    },

    redis: {
        title: 'Redis',
        match: (name, data) => name === 'redis' || data?.redis_version,
        fields: [
            {
                key: 'redis_version',
                type: 'inline',
                label: 'Version',
                getter: (data) => data?.info?.redis_version || data?.redis_version || data?.version
            },
            {
                key: 'redis_mode',
                type: 'inline',
                label: 'Mode',
                getter: (data) => data?.info?.redis_mode || data?.mode
            },
            { key: 'os', type: 'inline', label: 'OS', getter: (data) => data?.info?.os },
            { key: 'connected_clients', type: 'inline', label: 'Clients', getter: (data) => data?.info?.connected_clients },
            { key: 'used_memory_human', type: 'inline', label: 'Memory', getter: (data) => data?.info?.used_memory_human }
        ]
    },

    mongodb: {
        title: 'MongoDB',
        match: (name, data) => name === 'mongodb' || data?.build_info,
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'gitVersion', type: 'inline', label: 'Git Version', getter: (data) => data?.build_info?.gitVersion },
            { key: 'sysInfo', type: 'row', label: 'System Info', long: true, getter: (data) => data?.build_info?.sysInfo }
        ]
    },

    mysql: {
        title: 'MySQL',
        match: (name, data) => name === 'mysql' || data?.auth_plugin || data?.protocol === 'mysql',
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'auth_plugin', type: 'inline', label: 'Auth Plugin' }
        ]
    },

    vnc: {
        title: 'VNC',
        match: (name, data) => name === 'vnc' || data?.security_types,
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'desktop_name', type: 'inline', label: 'Desktop' },
            {
                key: 'resolution',
                type: 'inline',
                label: 'Resolution',
                getter: (data) => data?.width && data?.height ? `${data.width}x${data.height}` : null
            },
            { key: 'authentication_required', type: 'bool', label: 'Auth Required' },
            { key: 'security_types', type: 'tags', label: 'Security Types' }
        ]
    },

    dns: {
        title: 'DNS',
        match: (name, data) => ['dns', 'domain'].includes(name) || data?.recursion_available !== undefined,
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'hostname', type: 'inline', label: 'Hostname' },
            { key: 'recursion_available', type: 'bool', label: 'Recursion' },
            { key: 'dnssec', type: 'bool', label: 'DNSSEC' },
            { key: 'supports_zone_transfer', type: 'bool', label: 'Zone Transfer' }
        ]
    },

    smb: {
        title: 'SMB',
        match: (name, data) => ['smb', 'microsoft-ds'].includes(name) || data?.is_smb,
        fields: [
            { key: 'version_string', type: 'inline', label: 'Version', getter: (data) => data?.smb_version?.version_string },
            { key: 'netbios_name', type: 'inline', label: 'NetBIOS Name' },
            { key: 'domain_name', type: 'inline', label: 'Domain' },
            { key: 'os_version', type: 'row', label: 'OS Version' },
            { key: 'has_ntlm', type: 'bool', label: 'NTLM Auth' },
            {
                key: 'message_signing_enabled',
                type: 'bool',
                label: 'Signing Enabled',
                getter: (data) => data?.security_mode?.message_signing_enabled
            },
            {
                key: 'message_signing_required',
                type: 'bool',
                label: 'Signing Required',
                getter: (data) => data?.security_mode?.message_signing_required
            },
            { key: 'shares', type: 'custom', renderer: 'renderSMBShares' }
        ]
    },

    rpc: {
        title: 'RPC / Portmapper',
        match: (name, data) => ['rpcbind', 'portmapper', 'sunrpc'].includes(name) || data?.is_rpc,
        fields: [
            { key: 'is_rpc', type: 'bool', label: 'RPC Service' },
            {
                key: 'nfs_found',
                type: 'bool',
                label: 'NFS Exported',
                style: (value) => value ? 'success' : null
            },
            { key: 'exports', type: 'custom', renderer: 'renderNFSExports' },
            { key: 'services', type: 'custom', renderer: 'renderRPCServices' }
        ]
    },

    rdp: {
        title: 'RDP / Terminal Server',
        match: (name, data) => ['ms-wbt-server', 'rdp'].includes(name) || data?.protocol === 'rdp',
        fields: [
            { key: 'certificate_cn', type: 'inline', label: 'Certificate CN' },
            { key: 'netbios_computer_name', type: 'inline', label: 'NetBIOS Computer Name' },
            { key: 'dns_computer_name', type: 'inline', label: 'DNS Computer Name' },
            { key: 'security_protocol', type: 'inline', label: 'Security' },
            { key: 'tls_version', type: 'inline', label: 'TLS Version', getter: (data) => data?.tls?.version },
            { key: 'tls_cipher', type: 'inline', label: 'Cipher Suite', getter: (data) => data?.tls?.cipher_suite }
        ]
    },

    ssh: {
        title: 'SSH',
        match: (name) => name === 'ssh',
        fields: [
            { key: 'banner', type: 'row', label: 'Banner', long: true },
            { key: 'server_version', type: 'inline', label: 'Version' },
            { key: 'kex_algorithms', type: 'tags', label: 'Key Exchange' },
            { key: 'host_key_algorithms', type: 'tags', label: 'Host Key Algorithms' },
            { key: 'ciphers', type: 'tags', label: 'Ciphers' },
            { key: 'macs', type: 'tags', label: 'MACs' }
        ]
    },

    telnet: {
        title: 'Telnet',
        match: (name) => name === 'telnet',
        fields: [
            { key: 'banner', type: 'row', label: 'Banner', long: true },
            { key: 'options', type: 'tags', label: 'Options' }
        ]
    },

    postgres: {
        title: 'PostgreSQL',
        match: (name, data) => name === 'postgres' || data?.protocol === 'postgres',
        fields: [
            { key: 'ssl_supported', type: 'bool', label: 'SSL Supported' },
            { key: 'parameters', type: 'custom', renderer: 'renderKeyValueMap' }
        ]
    },

    ldap: {
        title: (data, name) => name === 'ldaps' ? 'LDAPS' : 'LDAP',
        match: (name) => ['ldap', 'ldaps'].includes(name),
        fields: [
            { key: 'dns_hostname', type: 'inline', label: 'DNS Hostname' },
            { key: 'server_name', type: 'inline', label: 'Server Name' },
            { key: 'domain', type: 'inline', label: 'Domain' },
            { key: 'naming_contexts', type: 'tags', label: 'Naming Contexts' },
            { key: 'supported_sasl_mechanisms', type: 'tags', label: 'SASL Mechanisms' },
            { key: 'supported_ldap_version', type: 'tags', label: 'LDAP Versions' }
        ]
    },

    mqtt: {
        title: 'MQTT',
        match: (name) => name === 'mqtt',
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'connected', type: 'bool', label: 'Connected' },
            { key: 'return_code_description', type: 'inline', label: 'Return Code' },
            { key: 'session_present', type: 'bool', label: 'Session Present' }
        ]
    },

    nfs: {
        title: 'NFS',
        match: (name, data) => name === 'nfs' || data?.protocol === 'nfs',
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'exports', type: 'tags', label: 'Exports' }
        ]
    },

    snmp: {
        title: 'SNMP',
        match: (name) => name === 'snmp',
        fields: [
            { key: 'version', type: 'inline', label: 'Version' },
            { key: 'sys_descr', type: 'row', label: 'System Description', long: true },
            { key: 'sys_name', type: 'inline', label: 'Name' },
            { key: 'sys_location', type: 'inline', label: 'Location' },
            { key: 'sys_contact', type: 'inline', label: 'Contact' },
            { key: 'community', type: 'inline', label: 'Community' },
            { key: 'hostname', type: 'inline', label: 'Hostname' }
        ]
    }
};

// ==================== Data Parsers ====================

const DATA_PARSERS = {
    // Parse array field that might be string, JSON string, or already an array
    array: function(value) {
        if (!value) return null;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') {
            try {
                const parsed = JSON.parse(value);
                return Array.isArray(parsed) ? parsed : [parsed];
            } catch {
                return value.includes(',') ? value.split(',').map(s => s.trim()) : [value];
            }
        }
        return null;
    }
};

// Export for use in main file
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { SERVICE_RENDERERS, DATA_PARSERS };
}
