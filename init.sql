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
    src_device_name TEXT,
    dst_device_name TEXT,
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

-- Indexes for newly exposed filters
CREATE INDEX IF NOT EXISTS idx_logs_src_port     ON logs (src_port) WHERE src_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_dst_port     ON logs (dst_port) WHERE dst_port IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_logs_protocol     ON logs (protocol) WHERE protocol IS NOT NULL;

-- Retention cleanup function (configurable periods)
CREATE OR REPLACE FUNCTION cleanup_old_logs(
    general_days INTEGER DEFAULT 60,
    dns_days INTEGER DEFAULT 10
) RETURNS INTEGER AS $$
DECLARE
    deleted INTEGER;
BEGIN
    IF general_days IS NULL OR dns_days IS NULL OR general_days <= 0 OR dns_days <= 0 THEN
        RAISE EXCEPTION 'cleanup_old_logs: days must be positive (general_days=%, dns_days=%)', general_days, dns_days;
    END IF;
    DELETE FROM logs
    WHERE (log_type = 'dns' AND timestamp < NOW() - (dns_days || ' days')::INTERVAL)
       OR (log_type != 'dns' AND timestamp < NOW() - (general_days || ' days')::INTERVAL);
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

-- UniFi client cache (Phase 2: IP-to-device-name enrichment)
CREATE TABLE IF NOT EXISTS unifi_clients (
    mac             MACADDR PRIMARY KEY,
    ip              INET,
    device_name     TEXT,
    hostname        TEXT,
    oui             TEXT,
    network         TEXT,
    essid           TEXT,
    vlan            INTEGER,
    is_fixed_ip     BOOLEAN DEFAULT FALSE,
    is_wired        BOOLEAN,
    last_seen       TIMESTAMPTZ,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_unifi_clients_ip ON unifi_clients (ip);
CREATE INDEX IF NOT EXISTS idx_unifi_clients_name ON unifi_clients (device_name) WHERE device_name IS NOT NULL;

-- UniFi infrastructure device cache (Phase 2)
CREATE TABLE IF NOT EXISTS unifi_devices (
    mac             MACADDR PRIMARY KEY,
    ip              INET,
    device_name     TEXT,
    model           TEXT,
    shortname       TEXT,
    device_type     TEXT,
    firmware        TEXT,
    serial          TEXT,
    state           INTEGER,
    uptime          BIGINT,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_unifi_devices_ip ON unifi_devices (ip);

-- Dynamic configuration store (setup wizard, interface labels, etc.)
CREATE TABLE IF NOT EXISTS system_config (
    key         TEXT PRIMARY KEY,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
