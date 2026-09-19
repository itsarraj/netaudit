/// Ports for services that are almost never meant to be directly
/// internet-facing — a database, cache, or admin API bound to `0.0.0.0`
/// is usually a mistake, not a decision, unlike a web server on 80/443/
/// 3000/8080 which is *supposed* to be reachable from anywhere. `None`
/// for a port not on this list doesn't mean "safe to expose," just
/// "not flagged with extra severity" — being bound to every interface is
/// already reported regardless.
pub fn risky_service_name(port: u16) -> Option<&'static str> {
    match port {
        5432 => Some("PostgreSQL"),
        3306 => Some("MySQL/MariaDB"),
        6379 => Some("Redis"),
        27017..=27019 => Some("MongoDB"),
        9200 | 9300 => Some("Elasticsearch"),
        11211 => Some("Memcached"),
        5984 => Some("CouchDB"),
        15672 => Some("RabbitMQ management UI"),
        5672 => Some("RabbitMQ"),
        2375 => Some("Docker API (unauthenticated by default!)"),
        2376 => Some("Docker API (TLS)"),
        9092 => Some("Kafka"),
        2181 => Some("ZooKeeper"),
        8086 => Some("InfluxDB"),
        9042 => Some("Cassandra"),
        1433 => Some("SQL Server"),
        1521 => Some("Oracle DB"),
        21 => Some("FTP"),
        23 => Some("Telnet"),
        3389 => Some("RDP"),
        6380 => Some("Redis (alt port)"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_common_database_ports() {
        assert_eq!(risky_service_name(5432), Some("PostgreSQL"));
        assert_eq!(risky_service_name(6379), Some("Redis"));
        assert_eq!(risky_service_name(27017), Some("MongoDB"));
    }

    #[test]
    fn ordinary_web_ports_are_not_flagged_as_risky_services() {
        assert_eq!(risky_service_name(80), None);
        assert_eq!(risky_service_name(443), None);
        assert_eq!(risky_service_name(3000), None);
        assert_eq!(risky_service_name(8080), None);
    }
}
