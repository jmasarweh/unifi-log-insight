-- UniFi Log Insight schema

CREATE TABLE IF NOT EXISTS logs (
    id          BIGSERIAL PRIMARY KEY,
    timestamp   TIMESTAMPTZ NOT NULL,
    log_type    VARCHAR(20) NOT NULL,  -- firewall, dhcp, dns, wifi, ids
    direction   VARCHAR(20),           -- inbound, outbound, inter_vlan, nat
    src_ip      INET,
    src_port    INTEGER,
    dst_ip      INET,
    dst_port    INTEGER,
    protocol    VARCHAR(10),
    service_name TEXT,
    rule_name   VARCHAR(100),
    rule_desc   VARCHAR(255),
    rule_action VARCHAR(20),           -- allow, block, redirect
    interface_in  VARCHAR(20),
    interface_out VARCHAR(20),
    mac_address MACADDR,
    hostname    VARCHAR(255),
    dns_query   VARCHAR(255),
    dns_type    VARCHAR(10),
    dns_answer  VARCHAR(255),
    dhcp_event  VARCHAR(20),           -- DHCPACK, DHCPDISCOVER, DHCPOFFER, DHCPREQUEST
    wifi_event  VARCHAR(50),
    geo_country VARCHAR(2),
    geo_city    VARCHAR(100),
    geo_lat     DECIMAL(9,6),
    geo_lon     DECIMAL(9,6),
    asn_number  INTEGER,
    asn_name    VARCHAR(255),
    threat_score    INTEGER,           -- 0-100 from AbuseIPDB
    threat_categories TEXT[],
    rdns        VARCHAR(255),
    abuse_usage_type TEXT,
    abuse_hostnames TEXT,
    abuse_total_reports INTEGER,
    abuse_last_reported TIMESTAMPTZ,
    abuse_is_whitelisted BOOLEAN,
    abuse_is_tor BOOLEAN,
    raw_log     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX IF NOT EXISTS idx_logs_timestamp    ON logs (timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type         ON logs (log_type);
CREATE INDEX IF NOT EXISTS idx_logs_src_ip       ON logs (src_ip);
CREATE INDEX IF NOT EXISTS idx_logs_dst_ip       ON logs (dst_ip);
CREATE INDEX IF NOT EXISTS idx_logs_rule_action  ON logs (rule_action);
CREATE INDEX IF NOT EXISTS idx_logs_direction    ON logs (direction);
CREATE INDEX IF NOT EXISTS idx_logs_threat_score ON logs (threat_score) WHERE threat_score IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_service_name ON logs (service_name) WHERE service_name IS NOT NULL;

-- Composite index for common filtered queries
CREATE INDEX IF NOT EXISTS idx_logs_type_time    ON logs (log_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_logs_action_time  ON logs (rule_action, timestamp DESC);

-- Retention cleanup function
-- DNS: 10 days, everything else: 60 days
CREATE OR REPLACE FUNCTION cleanup_old_logs() RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    DELETE FROM logs
    WHERE (log_type = 'dns' AND timestamp < NOW() - INTERVAL '10 days')
       OR (log_type != 'dns' AND timestamp < NOW() - INTERVAL '60 days');
    GET DIAGNOSTICS deleted = ROW_COUNT;
    RETURN deleted;
END;
$$ LANGUAGE plpgsql;

-- AbuseIPDB threat score cache (persistent across restarts)
CREATE TABLE IF NOT EXISTS ip_threats (
    ip              INET PRIMARY KEY,
    threat_score    INTEGER NOT NULL DEFAULT 0,
    threat_categories TEXT[],
    looked_up_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    abuse_usage_type TEXT,
    abuse_hostnames TEXT,
    abuse_total_reports INTEGER,
    abuse_last_reported TIMESTAMPTZ,
    abuse_is_whitelisted BOOLEAN,
    abuse_is_tor BOOLEAN
);

CREATE INDEX IF NOT EXISTS idx_ip_threats_looked_up ON ip_threats (looked_up_at);

-- Dynamic configuration store (setup wizard, interface labels, etc.)
CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
