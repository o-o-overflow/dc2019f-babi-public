use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::io::{Write, BufReader};
use regex::Regex;
use base64;
use libotp::totp;
use rand::Rng;

use crate::errors::*;
use crate::php::{serialize, unserialize, PhpVar};
use crate::http::{HttpRequest, HttpResponse};

pub struct Route {
    method: String,
    matcher: Regex,
    handler: fn(&HttpRequest) -> Result<HttpResponse>
}

pub struct App {
    routes: Vec<Route>
}

impl App {
    pub fn new() -> Self {
        App {
            routes: vec![]
        }
    }

    pub fn reg(&mut self, method: &str, re: Regex, handler: fn(&HttpRequest) -> Result<HttpResponse>) -> &mut Self {
        let r = Route {
            method: method.to_string(),
            matcher: re,
            handler: handler
        };
        self.routes.push(r);
        self
    }

    pub fn run(&self, fd: i32) {
        let mut istream = BufReader::new(unsafe {File::from_raw_fd(fd)});
        let mut ostream = unsafe {File::from_raw_fd(fd)};

        loop {
            match HttpRequest::from_stream::<File>(&mut istream) {
                Ok(req) => {
                    // println!("{:?}", req);
                    if self.route(&req)
                        .set_option("Connection".to_string(), 
                                    (if req.keep_alive() { "keep-alive" } else { "close" }).to_string())
                        .to_stream(&mut ostream)
                        .is_err() {
                            break;
                        }
                    if !req.keep_alive() {
                        break;
                    }
                },
                _ => {
                    break;
                }
            }
        }
    }

    fn route(&self, req: &HttpRequest) -> HttpResponse {
        for r in &self.routes {
            if r.method == req.method() && r.matcher.is_match(req.path()) {
                if let Ok(resp) = (r.handler)(req) {
                    return resp;
                } else {
                    return HttpResponse::new(500, b"internal server error".to_vec())
                }
            }
        }
        HttpResponse::new(404, b"not found".to_vec())
    }
}

pub fn index(_req: &HttpRequest) -> Result<HttpResponse> {
    Ok(HttpResponse::new(200, r#"<html><body><h1>Authenticator</h1><a href="/gen"><h2>generate</h2></a><a href="/list"><h2>list</h2></a></body></html>"#.as_bytes().to_vec()))
}

pub fn gen(_req: &HttpRequest) -> Result<HttpResponse> {
    let mut rng = rand::thread_rng();
    let charset: &'static [u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let secret: String = (0..32).map(|_| charset[rng.gen::<usize>() % 32] as char).collect();

    Ok(HttpResponse::new(200, format!(r#"<html><body><h1>Authenticator</h1><hr><form action="/enroll" method="POST">
Label:<br/>
<input type="text" name="label" value="demo" size=40>
<br/>
Secret:<br>
<input type="text" name="secret" value="{}" size=40>
<br><br>
<input type="submit" value="enroll">
</form> 
<img src="https://api.qrserver.com/v1/create-qr-code/?size=150x150&data=otpauth://totp/babi:demo?secret={}%26issuer=babi"></img>
</body></html>"#, secret, secret).as_bytes().to_vec()))
}

pub fn list(req: &HttpRequest) -> Result<HttpResponse> {
    let mut resp = b"<html><body><h1>Authenticator</h1><hr>".to_vec();
    if let Ok(param) = req.get(b"session") {
        if let PhpVar::Array(k, v) = *unserialize(&base64::decode(param)?) {
            for i in 0..k.len() {
                if let PhpVar::String(ref s) = *v[i] {
                    if let Some(code) = totp(&String::from_utf8_lossy(s), 6, 30, 0) {
                        write!(resp, r#"Label: {}<br/>Secret: {}<br/>Code: {:06}<hr>"#, k[i], v[i], code)?;
                        continue;
                    }
                }
                write!(resp, r#"Label: {}<br/>Secret: {}<br/>Code: INVALID<hr>"#, k[i], v[i])?;
            }
        }
    }
    write!(resp, "</body></html>")?;
    Ok(HttpResponse::new(200, resp))
}

pub fn info(req: &HttpRequest) -> Result<HttpResponse> {
    let mut resp = vec![];
    write!(resp, "<html><body><h1>Request</h1><p>{:?}</p>", req)?;
    /*
    for (k, v) in req.env {
        resp.extend_from_slice(format!("{:?}", req).as_bytes());
    }
    */
    if let Ok(param) = req.get(b"session") {
        let session = unserialize(&base64::decode(param)?);
        write!(resp, "<h1>Session</h1><p>{:?}</p>", session)?;
    }
    write!(resp, "</body></html>")?;
    Ok(HttpResponse::new(200, resp))
}

pub fn enroll(req: &HttpRequest) -> Result<HttpResponse> {
    let label = req.get(b"label")?;
    let secret = req.get(b"secret")?;

    let mut k = vec![];
    let mut v = vec![];
    if let Ok(param) = req.get(b"session") {
        if let PhpVar::Array(k_, v_) = *unserialize(&base64::decode(param)?) {
            k.extend(k_);
            v.extend(v_);
        }
    }
    k.push(Box::new(PhpVar::String(label.to_vec())));
    v.push(Box::new(PhpVar::String(secret.to_vec())));

    let session = PhpVar::Array(k, v);
    let cookie = format!("session={};", base64::encode(&serialize(&session)?));

    let mut resp = HttpResponse::new(301, vec![]);
    resp.set_option("Location".to_string(), "/list".to_string())
        .set_option("Set-Cookie".to_string(), cookie);
    Ok(resp)
}

#[cfg(test)]
fn local_request(payload: &mut [u8], handler: fn(&HttpRequest) -> Result<HttpResponse>) -> Result<HttpResponse> {
    let mut istream = BufReader::new(&payload[..]);
    let req = HttpRequest::from_stream(&mut istream)?;
    handler(&req)
}

/*
#[test]
fn exploit_leak() -> Result<()> {
    let mut payload = vec![];
    // write!(payload, "GET /index HTTP/1.1\r\n\r\n")?;
    write!(payload, "POST /enroll?session={}&label=1&secret=2 HTTP/1.1\r\nHTTP_RUST_BACKTRACE: full\r\n\r\n",
           base64::encode(&b"s:18446744073709551611:\"\";"))?;
    let resp = local_request(&mut payload[..], enroll)?;
    println!("{:?}", String::from_utf8_lossy(resp.content()));
    Ok(())
}
*/

#[test]
fn test_enroll() -> Result<()> {
    let mut payload = vec![];
    let label = "1";
    let secret = "2";
    let session = PhpVar::Array(
        vec![Box::new(PhpVar::String(b"a".to_vec()))],
        vec![Box::new(PhpVar::String(b"b".to_vec()))],
        );
    write!(payload, "POST /enroll?session={}&label={}&secret={} HTTP/1.1\r\n\r\n",
           base64::encode(&serialize(&session)?),
           label, secret)?;
    let resp = local_request(&mut payload[..], enroll)?;
    r#"
    php > var_dump(unserialize(base64_decode('YToyOntzOjE6ImEiO3M6MToiYiI7czoxOiIxIjtzOjE6IjIiO30')));
    array(2) {
      ["a"]=>
      string(1) "b"
      [1]=>
      string(1) "2"
    }"#;
    assert_eq!(resp.get_option("Set-Cookie")?, "session=YToyOntzOjE6ImEiO3M6MToiYiI7czoxOiIxIjtzOjE6IjIiO30=;");
    Ok(())
}
