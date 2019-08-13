#[macro_use] extern crate error_chain;

pub mod errors {
    error_chain! {
        foreign_links {
            IoError(::std::io::Error);
            B64Error(base64::DecodeError);
            ParseFloatError(::std::num::ParseFloatError);
            ParseIntError(::std::num::ParseIntError);
            FromUtf8Error(std::string::FromUtf8Error);
        }

        errors {
            Unknown {
                description("unknown")
                    display("unknown")
            }
            Invalid {
                description("invalid")
                    display("invalid")
            }
        }
    }
}

pub mod http;
pub mod php;
pub mod app;
