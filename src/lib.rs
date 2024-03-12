use std::sync::{Arc};
use rustls::Session;
use std::net::{TcpStream, ToSocketAddrs};
use std::io::{Write, Error, ErrorKind};
use std::time::Duration;
use base64::Engine;
use base64::engine::general_purpose;
use url::Url;
use x509_parser::{parse_x509_der};


pub struct DomainCert();

impl DomainCert {

    pub fn from_url(url_str: &str,time_out: u64) -> Result<String, std::io::Error> {

        let url_string;
        if !url_str.starts_with("https") {
            url_string=  format!("https://{}", url_str.to_string());
        }else{
            url_string = url_str.to_string();
        }

        let target_url = Url::parse(&url_string)
            .map_err(|e|Error::new(ErrorKind::InvalidInput, e.to_string()))?;

        let domain = target_url
            .host_str().ok_or(Error::new(ErrorKind::InvalidInput, "host not found"))?;
        let port = target_url
            .port_or_known_default().ok_or(Error::new(ErrorKind::InvalidInput, "port not found"))?;
        let addr = format!("{}:{}", domain,port);

        let mut config = rustls::ClientConfig::new();
        config.root_store.add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        let rc_config = Arc::new(config);
        let site = match webpki::DNSNameRef::try_from_ascii_str(domain) {
            Ok(val) => val,
            Err(e) => return Err(Error::new(ErrorKind::InvalidInput, e.to_string())),
        };
        let socket_addr = addr.to_socket_addrs()
            .map_err(|e|Error::new(ErrorKind::InvalidInput, e.to_string()))?
            .next().ok_or(Error::new(ErrorKind::InvalidInput,"addrs error"))?;
        let mut sess = rustls::ClientSession::new(&rc_config, site);
        let mut sock = TcpStream::connect_timeout(&socket_addr,Duration::from_secs(time_out))?;
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nConnection: \
                               close\r\nAccept-Encoding: identity\r\n\r\n",
                          domain);
        tls.write_all(req.as_bytes())?;


        if let Some(certificates) = tls.sess.get_peer_certificates() {
            for certificate in certificates.iter() {
                let x509cert = match parse_x509_der(certificate.as_ref()) {
                    Ok((_, x509cert)) => x509cert,
                    Err(e) => return Err(Error::new(ErrorKind::Other, e.to_string())),
                };

                let is_ca = match x509cert.tbs_certificate.basic_constraints() {
                    Some((_, basic_constraints)) => basic_constraints.ca,
                    None => false,
                };

                //check if it's ca or not, if ca then insert to intermediate certificate
                if !is_ca {
                    let cert_value = general_purpose::STANDARD.encode(certificate.as_ref());
                    // let cert = x509cert.tbs_certificate.as_ref();
                    // let cert_value = String::from_utf8(cert.to_vec()).unwrap();
                    println!("{}",cert_value);
                    return Ok(cert_value)
                }
            }

            Err(Error::new(ErrorKind::NotFound, "certificate not found".to_string()))
        } else {
            Err(Error::new(ErrorKind::NotFound, "certificate not found".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_ssl_server_is_valid() {

        match DomainCert::from_url("bank.pingan.com.cn",5) {
            Ok(cert) => println!("{}",cert),
            Err(err) =>println!("{}",err),
        }
    }

}
