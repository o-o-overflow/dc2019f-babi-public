extern crate nix;

use std::io;
use std::env;
use std::net::TcpListener;
use std::os::unix::io::{IntoRawFd, AsRawFd};
use std::process::exit;
use nix::unistd::*;
use nix::sys::signal::*;
use regex::Regex;
use rand::Rng;

use babi::app;

static mut UID: u32 = 65535;

extern fn signal_handler(_: i32) {
    unsafe {
        setuid(Uid::from_raw(UID)).expect("uid");
    }
    kill(Pid::from_raw(-1), SIGKILL).expect("kill");
    exit(1);
}

fn main() -> io::Result<()> {
    let mut timeout = 30;
    if let Some(arg) = env::args().nth(1) {
        timeout = u32::from_str_radix(&arg, 10).unwrap();
    }

    unsafe {
        sigaction(Signal::SIGCHLD, &SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty())).unwrap();
        sigaction(Signal::SIGALRM, &SigAction::new(SigHandler::Handler(signal_handler), SaFlags::empty(), SigSet::empty())).unwrap();
    }

    let mut app = app::App::new();
    app.reg("GET", Regex::new("^/$").unwrap(), app::index)
        .reg("GET", Regex::new("^/list$").unwrap(), app::list)
        .reg("GET", Regex::new("^/info$").unwrap(), app::info)
        .reg("GET", Regex::new("^/gen$").unwrap(), app::gen)
        .reg("POST", Regex::new("^/enroll$").unwrap(), app::enroll);

    let listener = TcpListener::bind("0.0.0.0:47793").unwrap(); // 0xbab1
    let server_fd = listener.as_raw_fd();

    for stream in listener.incoming() {
        match fork() {
            Ok(ForkResult::Child) => {
                close(server_fd).unwrap();

                unsafe {
                    let mut rng = rand::thread_rng();
                    UID = rng.gen::<u32>() % 30000 + 10000;
                }

                let client_fd = stream?.into_raw_fd();

                alarm::set(timeout);

                match fork().expect("fork failed") {
                    ForkResult::Child => {
                        unsafe {
                            let gid = Gid::from_raw(UID);
                            setgroups(&[gid]).expect("groups");
                            setgid(gid).expect("gid");
                            setuid(Uid::from_raw(UID)).expect("uid");
                        }

                        dup2(client_fd, 0).unwrap();
                        dup2(client_fd, 1).unwrap();
                        dup2(client_fd, 2).unwrap();
                        app.run(client_fd);
                        exit(0);
                    },
                    ForkResult::Parent{ child: _ } => {
                        close(client_fd).unwrap();
                        let _ = nix::sys::wait::wait();
                        signal_handler(0);
                    }
                }
            },
            Ok(ForkResult::Parent{ child: _ }) => {
                // logging
            },
            _ => (),
        }
    }
    Ok(())
}
