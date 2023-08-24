use std::net::IpAddr;

fn eq_with_mask(ip_octets: &[u8], mask: &[u8], net_octets: &[u8]) -> bool {
    assert!(ip_octets.len() == mask.len());
    assert!(ip_octets.len() == net_octets.len());
    for ((io, mo), no) in Iterator::zip(
        Iterator::zip(ip_octets.iter(), mask.iter()),
        net_octets.iter(),
    ) {
        if io & mo != *no {
            return false;
        }
    }
    true
}

fn cidr_to_mask(mask: &mut [u8], mut cidr_mask: u8) {
    for mi in mask.iter_mut() {
        if cidr_mask == 0 {
            *mi = 0;
        } else if cidr_mask < 8 {
            *mi = u8::MAX << (8 - cidr_mask);
            break;
        } else {
            *mi = u8::MAX;
            cidr_mask -= 8;
        }
    }
}

pub fn ip_in_net(ip: &IpAddr, net: &IpAddr, cidr_mask: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(i), IpAddr::V4(n)) => {
            let mut mask = [0; 4];
            cidr_to_mask(&mut mask, cidr_mask);
            eq_with_mask(&i.octets(), &mask, &n.octets())
        }
        (IpAddr::V6(i), IpAddr::V6(n)) => {
            let mut mask = [0; 16];
            cidr_to_mask(&mut mask, cidr_mask);
            println!("v6 mask {:?}", mask);
            eq_with_mask(&i.octets(), &mask, &n.octets())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_eq_fullmask() {
        assert!(super::eq_with_mask(
            &[127, 0, 0, 1],
            &[255, 255, 255, 255],
            &[127, 0, 0, 1]
        ));
    }

    #[test]
    fn test_eq_partialmask_1() {
        assert!(super::eq_with_mask(
            &[127, 0, 0, 1],
            &[255, 255, 255, 0],
            &[127, 0, 0, 0]
        ));
    }

    #[test]
    fn test_eq_partialmask_2() {
        assert!(super::eq_with_mask(
            &[127, 0, 0, 1],
            &[255, 255, 255, 254],
            &[127, 0, 0, 0]
        ));
    }

    #[test]
    fn test_eq_partialmask_3() {
        assert!(!super::eq_with_mask(
            &[127, 0, 0, 2],
            &[255, 255, 255, 254],
            &[127, 0, 0, 0]
        ));
    }

    #[test]
    fn test_eq_partialmask_4() {
        assert!(super::eq_with_mask(
            &[127, 0, 0, 1],
            &[0, 0, 0, 0],
            &[0, 0, 0, 0]
        ));
    }

    #[test]
    fn test_eq_cidr_1() {
        let mut mask = [0, 0, 0, 0];
        super::cidr_to_mask(&mut mask, 0);
        assert_eq!(mask, [0, 0, 0, 0]);
    }

    #[test]
    fn test_eq_cidr_2() {
        let mut mask = [0, 0, 0, 0];
        super::cidr_to_mask(&mut mask, 24);
        assert_eq!(mask, [255, 255, 255, 0]);
    }

    #[test]
    fn test_eq_cidr_3() {
        let mut mask = [0, 0, 0, 0];
        super::cidr_to_mask(&mut mask, 30);
        assert_eq!(mask, [255, 255, 255, 252]);
    }

    #[test]
    fn test_eq_cidr_4() {
        let mut mask = [0, 0, 0, 0];
        super::cidr_to_mask(&mut mask, 12);
        assert_eq!(mask, [255, 240, 0, 0]);
    }

    #[test]
    fn test_ip_net_1() {
        assert!(super::ip_in_net(
            &IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            &IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            12
        ));
    }

    #[test]
    fn test_ip_net_2() {
        assert!(super::ip_in_net(
            &IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255)),
            &IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            12
        ));
    }

    #[test]
    fn test_ip_net_3() {
        assert!(!super::ip_in_net(
            &IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1)),
            &IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
            12
        ));
    }

}
