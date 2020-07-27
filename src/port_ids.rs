use std::collections::HashMap;
use std::string::ToString;

pub fn port_map() -> HashMap<u16, String> {
    let mut port_id_map = HashMap::new();
    port_id_map.insert(7 as u16, "Echo".to_string());
    port_id_map.insert(19 as u16, "Chargen".to_string());
    port_id_map.insert(20 as u16, "FTP".to_string());
    port_id_map.insert(21 as u16, "FTP".to_string());
    port_id_map.insert(22 as u16, "SSH".to_string());
    port_id_map.insert(23 as u16, "Telnet".to_string());
    port_id_map.insert(25 as u16, "SMTP".to_string());
    port_id_map.insert(42 as u16, "WINS Replication".to_string());
    port_id_map.insert(43 as u16, "WHOIS".to_string());
    port_id_map.insert(49 as u16, "TACACS".to_string());
    port_id_map.insert(53 as u16, "DNS".to_string());
    port_id_map.insert(67 as u16, "DCHP".to_string());
    port_id_map.insert(69 as u16, "TFTP".to_string());
    port_id_map.insert(70 as u16, "Gopher".to_string());
    port_id_map.insert(79 as u16, "Finger".to_string());
    port_id_map.insert(80 as u16, "HTTP".to_string());
    port_id_map.insert(88 as u16, "Kerberos".to_string());
    port_id_map.insert(102 as u16, "MS Exchange".to_string());
    return port_id_map;
}