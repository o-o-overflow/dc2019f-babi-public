use std::io::{Write, Read, BufRead, BufReader};
use std::collections::HashMap;

use crate::errors::*;

#[derive(Debug)]
pub struct HttpRequest {
    keep_alive: bool,
    content_length: usize,
    method: String,
    path: String,
    body: Vec<u8>,
    env: HashMap<String, String>,
    vars: HashMap<Vec<u8>, Vec<u8>>,
}

impl HttpRequest {
    pub fn from_stream<T>(stream: &mut BufReader<T>) -> Result<Self> where T: Read {
        let method;
        let mut path;
        let mut env = HashMap::new();
        let mut vars = HashMap::new();

        // parse method/path
        {
            let mut buf = Vec::with_capacity(0x100);
            stream.read_until(b'\n', &mut buf)?;
            let s = String::from_utf8(buf)?;
            let v: Vec<&str> = s.split_whitespace().collect();
            if v.len() < 2 {
                bail!(ErrorKind::Invalid)
            }
            method = v[0].to_string();
            path = v[1].to_string();
        }

        fn parse_param(raw: &[u8], sep: u8, vars: &mut HashMap<Vec<u8>, Vec<u8>>) {
            for param in raw.split(|c| *c == sep) {
                for i in 0..param.len() {
                    if param[i] == b'=' {
                        let k = &param[..i];
                        let v = &param[(i + 1)..];
                        vars.insert(k.to_vec(), v.to_vec());
                        break;
                    }
                }
            }
        }

        // parse url
        if let Some(pos) = path.find('?') {
            parse_param(&path[(pos + 1)..].as_bytes(), b'&', &mut vars);
            path.truncate(pos);
        }

        // println!("method = {:?} path = {:?}", method, path);

        // options
        loop {
            let mut buf = Vec::with_capacity(0x100);
            if stream.read_until(b'\n', &mut buf)? == 2 {
                break;
            }
            let s = String::from_utf8(buf)?;
            let v: Vec<&str> = s.splitn(2, ": ").collect();
            if v.len() == 2 {
                env.insert(v[0].trim().to_uppercase(), v[1].trim().to_string());
            }
        }

        let mut keep_alive = false;
        if let Some(opt) = env.get("CONNECTION") {
            keep_alive = opt.to_lowercase() == "keep-alive";
        }

        let mut content_length = 0;
        if let Some(opt) = env.get("CONTENT-LENGTH") {
            content_length = opt.parse()?;
        }

        if let Some(cookie) = env.get("COOKIE") {
            parse_param(cookie.as_bytes(), b';', &mut vars);
        }

        for (k, v) in &env {
            if k.starts_with("HTTP_") {
                std::env::set_var(k.get(5..).unwrap(), v);
            }
        }

        let mut body = Vec::new();
        body.resize(content_length, 0);
        stream.read_exact(&mut body)?;

        // try parse body arguments
        parse_param(&body, b'&', &mut vars);

        Ok(HttpRequest {
            keep_alive: keep_alive,
            content_length: content_length,
            method: method,
            path: path,
            env: env,
            vars: vars,
            body: body
        })
    }

    pub fn keep_alive(&self) -> bool {
        self.keep_alive
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn method(&self) -> &str {
        &self.method
    }

    pub fn get(&self, k: &[u8]) -> Result<&Vec<u8>> {
        match self.vars.get(k) {
            Some(v) => Ok(v),
            _ => bail!(ErrorKind::Unknown)
        }
    }
}

#[derive(Debug)]
pub struct HttpResponse {
    status: u32,
    response: Vec<u8>,
    env: HashMap<String, String>,
}

impl HttpResponse {
    pub fn new(status: u32, response: Vec<u8>) -> Self {
        let mut env = HashMap::new();
        env.insert("Content-Length".to_string(), response.len().to_string());
        HttpResponse {
            status: status,
            response: response,
            env: env
        }
    }

    #[inline]
    fn desc(&self) -> &str {
        match self.status {
            200 => "OK",
            301 => "Moved Permanently",
            404 => "Not Found",
            500 => "Internal Server Error",
            _ => "Unknown Error"
        }
    }

    #[inline]
    pub fn content(&self) -> &[u8] {
        &self.response
    }

    pub fn to_stream<T>(&self, stream: &mut T) -> Result<()> where T: Write {
        stream.write_fmt(format_args!("HTTP/1.1 {} {}\r\nServer: BABI/0.1\r\n", self.status, self.desc()))?;
        for (k, v) in &self.env {
            stream.write_fmt(format_args!("{}: {}\r\n", k, v))?;
        }
        stream.write_all(b"\r\n")?;
        stream.write_all(&self.response)?;
        Ok(())
    }

    pub fn set_option(&mut self, option: String, value: String) -> &mut Self {
        self.env.insert(option, value);
        self
    }

    pub fn get_option(&self, option: &str) -> Result<&str> {
        if let Some(v) = self.env.get(option) {
            Ok(&v)
        } else {
            bail!(ErrorKind::Invalid)
        }
    }
}
