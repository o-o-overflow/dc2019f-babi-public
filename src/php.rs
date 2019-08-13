use std::fmt;
use std::fmt::Write;
use std::str::FromStr;

use crate::errors::*;

#[derive(PartialEq)]
pub enum PhpVar {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(Vec<u8>),
    Array(Vec<Box<PhpVar>>, Vec<Box<PhpVar>>),
    Ref(usize),
}

impl fmt::Display for PhpVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PhpVar::Null => Ok(()),
            PhpVar::Bool(b) => write!(f, "{}", b as u8),
            PhpVar::Int(i) => write!(f, "{}", i),
            PhpVar::Float(d) => write!(f, "{}", d),
            PhpVar::String(ref s) => {
                for c in s {
                    f.write_char(*c as char)?;
                }
                Ok(())
            },
            PhpVar::Array(_, _) => write!(f, "Array"),
            _ => write!(f, "undefined")
        }
    }
}

impl fmt::Debug for PhpVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            PhpVar::Null => write!(f, "NULL"),
            PhpVar::Bool(b) => write!(f, "bool({})", b),
            PhpVar::Int(i) => write!(f, "int({})", i),
            PhpVar::Float(d) => write!(f, "float({})", d),
            PhpVar::String(ref s) => {
                write!(f, "string({}) \"", s.len())?;
                for c in s {
                    f.write_char(*c as char)?;
                }
                write!(f, "\"")
            },
            PhpVar::Array(ref k, ref v) => {
                write!(f, "array({}) {{", k.len())?;
                for i in 0..k.len() {
                    write!(f, "[\"{:}\"]\n=>{:?}\n", k[i], v[i])?;
                }
                write!(f, "}}")
            }
            _ => write!(f, "undefined")
        }
    }
}

#[derive(Debug)]
struct Parser<'a> {
    cur: usize,
    len: usize,
    raw: &'a [u8],
    has_ref: bool,
}

impl<'a> Parser<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Parser {
            cur: 0,
            len: raw.len(),
            raw: raw,
            has_ref: false
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        if self.cur < self.len {
            let i = self.cur;
            let c = self.raw[i] as u8;
            self.cur += 1;
            Ok(c)
        } else {
            bail!(ErrorKind::Invalid)
        }
    }

    fn expect_byte(&mut self, c: u8) -> Result<()> {
        if self.read_byte()? == c {
            Ok(())
        } else {
            bail!(ErrorKind::Invalid)
        }
    }

    fn read_number(&mut self) -> Result<i64> {
        let mut v: i64 = 0;
        let mut i = self.cur;
        while i < self.len && self.raw[i].is_ascii_digit() {
            v *= 10;
            v += self.raw[i] as i64 - 48;
            i += 1;
        }
        if i != self.cur {
            self.cur = i;
            Ok(v)
        } else {
            bail!(ErrorKind::Invalid)
        }
    }

    fn read_bool(&mut self) -> Result<Box<PhpVar>> {
        let v = self.read_number()?;
        self.expect_byte(b';')?;
        Ok(Box::new(PhpVar::Bool(v != 0)))
    }

    fn read_int(&mut self) -> Result<Box<PhpVar>> {
        let v = self.read_number()?;
        self.expect_byte(b';')?;
        Ok(Box::new(PhpVar::Int(v)))
    }

    fn read_ref(&mut self) -> Result<Box<PhpVar>> {
        let v = self.read_number()? as usize;
        self.expect_byte(b';')?;
        self.has_ref = true;
        Ok(Box::new(PhpVar::Ref(v)))
    }

    fn read_float(&mut self) -> Result<Box<PhpVar>> {
        let mut i = self.cur;
        while i < self.len && self.raw[i] != b';' {
            i += 1;
        }
        let s = String::from_utf8(self.raw[self.cur..i].to_vec())?;
        let f = f64::from_str(&s)?;
        self.cur = i;
        self.expect_byte(b';')?;
        Ok(Box::new(PhpVar::Float(f)))
    }

    fn read_string(&mut self) -> Result<Box<PhpVar>> {
        let l = self.read_number()? as usize;
        self.expect_byte(b':')?;
        self.expect_byte(b'"')?;

        let s = self.raw[self.cur..(self.cur + l)].to_vec();
        self.cur += l;

        self.expect_byte(b'"')?;
        self.expect_byte(b';')?;
        Ok(Box::new(PhpVar::String(s)))
    }

    fn read_array(&mut self) -> Result<Box<PhpVar>> {
        let l = self.read_number()? as usize;
        self.expect_byte(b':')?;
        self.expect_byte(b'{')?;

        let mut k = vec![];
        let mut v = vec![];

        for _i in 0..l {
            k.push(self.read_var()?);
            v.push(self.read_var()?);
        }

        self.expect_byte(b'}')?;

        Ok(Box::new(PhpVar::Array(k, v)))
    }

    fn read_var(&mut self) -> Result<Box<PhpVar>> {
        let _type = self.read_byte()?;

        if _type == b'N' {
            self.expect_byte(b';')?;
            Ok(Box::new(PhpVar::Null))
        } else {
            self.expect_byte(b':')?;
            match _type {
                b'b' => self.read_bool(),
                b'i' => self.read_int(),
                b'd' => self.read_float(),
                b's' => self.read_string(),
                b'a' => self.read_array(),
                b'r' => self.read_ref(),
                _ => bail!(ErrorKind::Unknown)
            }
        }
    }

    fn fixup(mut obj: Box<PhpVar>) -> Result<Box<PhpVar>> {
        let mut vars = vec![];
        fn travel(obj: &mut Box<PhpVar>, vars: &mut Vec<*mut PhpVar>) {
            vars.push(&mut **obj as *mut PhpVar);
            if let PhpVar::Array(_, ref mut v) = **obj {
                for v in v {
                    travel(v, vars);
                }
            }
        }
        travel(&mut obj, &mut vars);

        fn translate(obj: Box<PhpVar>, vars: &Vec<*mut PhpVar>) -> Result<Box<PhpVar>> {
            match *obj {
                PhpVar::Ref(id) => {
                    let id = id - 1;
                    if id >= vars.len() || vars[id] as *const PhpVar == &*obj {
                        bail!(ErrorKind::Invalid)
                    } else {
                        Ok(unsafe{ Box::from_raw(vars[id]) })
                    }
                },
                PhpVar::Array(k, v) => {
                    let mut _k = vec![];
                    for k in k {
                        _k.push(translate(k, vars)?);
                    }
                    let mut _v = vec![];
                    for v in v {
                        _v.push(translate(v, vars)?);
                    }
                    Ok(Box::new(PhpVar::Array(_k, _v)))
                }
                _ => Ok(obj)
            }
        }
        // println!("total vars = {}", vars.len());
        translate(obj, &vars)
    }
}

pub fn unserialize(raw: &[u8]) -> Box<PhpVar> {
    let mut parser = Parser::new(raw);
    if let Ok(v) = parser.read_var() {
        if parser.len == parser.cur {
            if !parser.has_ref {
                return v;
            } else {
                if let Ok(v) = Parser::fixup(v) {
                    return v;
                }
            }
        }
    }
    Box::new(PhpVar::Bool(false))
}

pub fn serialize(var: &PhpVar) -> Result<Vec<u8>> {
    match var {
        PhpVar::Null => Ok(b"N;".to_vec()),
        PhpVar::Bool(b) => Ok((if *b { b"b:1;" } else { b"b:0;" }).to_vec()),
        PhpVar::Int(i) => Ok(format!("i:{};", i).as_bytes().to_vec()),
        PhpVar::Float(f) => Ok(format!("d:{};", f).as_bytes().to_vec()),
        PhpVar::Ref(r) => Ok(format!("r:{};", r).as_bytes().to_vec()),
        PhpVar::String(s) => {
            let mut t = format!("s:{}:\"", s.len()).as_bytes().to_vec();
            t.extend_from_slice(&s);
            t.push(34); // "
            t.push(59); // ;
            Ok(t)
        },
        PhpVar::Array(k, v) => {
            let mut t = format!("a:{}:{{", k.len()).as_bytes().to_vec();
            for i in 0..k.len() {
                t.extend_from_slice(&serialize(&k[i])?);
                t.extend_from_slice(&serialize(&v[i])?);
            }
            t.push(125); // }
            Ok(t)
        }
    }
}

#[test]
fn test_basic_unserialize() {
    assert_ne!(*unserialize(b"N;"), PhpVar::Bool(false));
    assert_ne!(*unserialize(b"b:1;"), PhpVar::Bool(false));
    assert_ne!(*unserialize(b"i:123;"), PhpVar::Bool(false));
    assert_ne!(*unserialize(b"a:0:{}"), PhpVar::Bool(false));
    assert_ne!(*unserialize(b"s:4:\"abcd\";"), PhpVar::Bool(false));
    assert_ne!(*unserialize(b"a:1:{s:1:\"s\";i:1;}"), PhpVar::Bool(false));
}

#[test]
fn test_basic_serialize() -> Result<()> {
    assert_eq!(serialize(&PhpVar::Null)?, b"N;");
    assert_eq!(serialize(&PhpVar::Bool(true))?, b"b:1;");
    assert_eq!(serialize(&PhpVar::Int(123))?, b"i:123;");
    Ok(())
}

#[cfg(test)]
fn serialize_then_unserialize(raw: &[u8]) -> Result<()> {
    let var = unserialize(&raw);
    let res = serialize(&var)?;
    println!("{:?} {:?}", raw, res);
    assert_eq!(raw.to_vec(), res);
    Ok(())
}

#[test]
fn test_unserialize_serialize() -> Result<()> {
    serialize_then_unserialize(b"N;")?;
    serialize_then_unserialize(b"b:1;")?;
    serialize_then_unserialize(b"b:0;")?;
    serialize_then_unserialize(b"i:123;")?;
    serialize_then_unserialize(b"a:0:{}")?;
    serialize_then_unserialize(b"s:4:\"abcd\";")?;
    serialize_then_unserialize(b"a:1:{s:1:\"s\";i:1;}")?;
    Ok(())
}

/* NOTE: do not test because Ref is buggy
#[test]
fn test_unserialize_ref() -> Result<()> {
    assert_eq!(*unserialize(b"a:2:{i:0;a:0:{}i:1;r:3;}"), PhpVar::Bool(false));
    assert_eq!(serialize(&unserialize(b"a:2:{i:0;a:0:{}i:1;r:2;}"))?, b"a:2:{i:0;a:0:{}i:1;a:0:{}}");
    Ok(())
}
*/
