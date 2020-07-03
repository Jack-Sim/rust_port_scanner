use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::str::FromStr;
use std::process;
use std::sync::mpsc::{Sender, channel};
use std::thread;

// Max port we can sniff
const MAX: u16 = 65535;
const MIN_THREADS: u16 = 10;

struct Arguments {
    flag1: String,
    flag2: String,
    ipaddr: IpAddr,
    threads: u16,
    ports: u16,
}

impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2{
            return Err("Not enough arguments");
        } else if args.len() > 6{
            return Err("Too many arguments");
        }
        let f = args[1].clone();
        // Check if the first argument is an ip address
        // if it is assign f as an ip address to ipaddr and autocomplete the
        // other elements of the Arguments structure
        if let Ok(ipaddr) = IpAddr::from_str(&f){
            return Ok(Arguments {flag1: String::from(""), flag2: String::from(""), ipaddr, threads: MIN_THREADS, ports: MAX});
        } else {
            // Otherwise the first argument should be a flag
            let flag1 = args[1].clone();
            // Check what is inside flag
            if flag1.contains("-h") || flag1.contains("-help") && args.len() == 2{
                // if the flag is -h or -help and the number of arguments is 2 display help message
                println!("Usage: 
                \n\r    -j or -threads to select how many threads you want
                \n\r    -h or -help to show this help message
                \n\r    -p or -ports to set the max port to be scanned
                \n\rExamples:
                \n\r    ip_sniffer 192.168.1.1 : Scans router for open ports with default threading
                \n\r    ip_sniffer -j 100 192.168.1.1 : Scans router with 100 threads
                \n\r    ip_sniffer -p 1000 192.168.1.1 : Scan first 1000 ports of a router
                \n\r    ip_sniffer -j 100 -p 1000 192.168.1.1 : Scans first 1000 ports of router with 100 threads");
                return Err("help");
            } else if flag1.contains("-h") || flag1.contains("-help") {
                // if the flag is -h or -help but there are more than 2 arguments raise an error
                return Err("Too many arguments, use -h or -help to display usage guide");
            } else if args.len() == 4 {
                if flag1.contains("-j") || flag1.contains("-threads") {
                    // If the flag contains -j assign the ipaddr to args[3]
                    let ipaddr = match IpAddr::from_str(&args[3]){
                        // Unwrap value inside Ok and parse it to ipaddr
                        Ok(s) => s,
                        Err(_) => return Err("Not a valid IPADDR; must be IPv4 or IPv6")
                    };
                    // check if the argument in position 2 is a u16 integer
                    let threads = match args[2].parse::<u16>(){
                        Ok(s) => s,
                        Err(_) => return Err("Failed to parse thread number")
                    };
                    return Ok(Arguments {threads, flag1, ipaddr, ports: MAX, flag2: String::from("")});
                
                } else if flag1.contains("-p") || flag1.contains("-ports") {
                    // If the flag contains -p assign the ipaddr to args[3]
                    let ipaddr = match IpAddr::from_str(&args[3]){
                        // Unwrap value inside Ok and parse it to ipaddr
                        Ok(s) => s,
                        Err(_) => return Err("Not a valid IPADDR; must be IPv4 or IPv6")
                    };
                    let ports = match args[2].parse::<u16>(){
                        Ok(s) => s,
                        Err(_) => return Err("Failed to parse port number")
                    };

                    return Ok(Arguments {threads: MIN_THREADS, flag1, ipaddr, ports, flag2: String::from("")});
                } else {
                    return Err("Invalid syntax");
                }
            } else if args.len() == 6 {
                let mut valid_flags: [String; 4] = ["-j".to_string(), "-threads".to_string(), "-p".to_string(), "-ports".to_string()];
                let flag2 = args[3].clone();
                let ipaddr = match IpAddr::from_str(&args[5]){
                    // Unwrap value inside Ok and parse it to ipaddr
                    Ok(s) => s,
                    Err(_) => return Err("Not a valid IPADDR; must be IPv4 or IPv6")
                };
                if flag1 == flag2 {
                    return Err("Entered same flag twice, refer to -h for usage guide");
                } else if valid_flags.contains(&args[1]) && valid_flags.contains(&args[3]){
                    if flag1.contains("-j") || flag1.contains("-threads") {
                        let threads = match args[2].parse::<u16>(){
                            Ok(s) => s,
                            Err(_) => return Err("Failed to parse thread number")
                        };
                    }
                    if flag2.contains("-j") || flag2.contains("-threads") {
                        let threads = match args[2].parse::<u16>(){
                            Ok(s) => s,
                            Err(_) => return Err("Failed to parse thread number")
                        };
                    } 
                    if flag1.contains("-p") || flag1.contains("-ports") {
                        let ports = match args[2].parse::<u16>(){
                            Ok(s) => s,
                            Err(_) => return Err("Failed to parse port number")
                        };
                    }
                    if flag2.contains("-p") || flag2.contains("-ports") {
                        let ports = match args[2].parse::<u16>(){
                            Ok(s) => s,
                            Err(_) => return Err("Failed to parse port number")
                        };
                    }
                    //println!("Flag1: {}, Flag2: {}, Threads: {}, Ports: {}", flag1, flag2, threads, ports);
                    return Ok(Arguments {flag1, flag2, threads: MIN_THREADS, ports:1000, ipaddr});
                
                } else {
                    return Err("Invalid Syntax");
                } 
                
            }else {
                return Err("Too many arguments")
            }
        }
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16, max_ports: u16){
    let mut port: u16 = start_port + 1;
    loop{
        
        match TcpStream::connect((addr, port)){
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (max_ports - port) <= num_threads{
            break;
        }
        port += num_threads;
    }
}

fn main() {
    // take all arguments passed to program and store them as a vector of strings
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    // try to create the arguments instance or raise error
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err| {
            if err.contains("help") {
                // if error is help close program
                process::exit(0);
            } else {
                // if error is not help print error then close program
                eprintln!("{} problem parsing arguments: {}", program, err);
                process::exit(0);
            }
        }
    );
    // assign threads to num_threads
    let num_threads = arguments.threads;
    // extract transmitter and receiver from channel()
    let (tx, rx) = channel();
    let addr = arguments.ipaddr;
    let max_ports = arguments.ports;
    for i in 0..num_threads{
        let tx = tx.clone();
        thread::spawn(move || {
            scan(tx, i, addr, num_threads, max_ports);
        });
    }

    let mut out = vec![];
    drop(tx);
    for p in rx{
        out.push(p);
    }
    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}

