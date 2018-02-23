extern crate tiny_http;
use tiny_http::{Server, Response, Request, Header, StatusCode};

extern crate serde;
extern crate serde_json;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate lazy_static;

//use serde_json::Error;

extern crate url;
//use url::{Url, ParseError};

//use std::collections::HashMap;
use std::process::{Command,Stdio};
use std::fs::File;
//use std::io::prelude::*;
use std::thread;
use std::time::Duration;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Read,Write};
use std::path::{Path};
use std::fs;

#[derive(Serialize, Deserialize, Clone)]
struct Person {
  name: String,
  uin: String,
  email: String,
  mac: String,
}

impl Person {
  pub fn is_present(&self) -> bool {
    return ping_bt_mac(&self.mac);
  }
  pub fn scan(&self) -> ScanReceipt {
    return ScanReceipt::scan(&self.mac);
  }
}

struct ScanReceipt {
  mac: String,
  epoch_s: u64,
  present: bool,
}

impl ScanReceipt {
  pub fn scan(mac: &String) -> ScanReceipt {
    let epoch_s = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time.exe has failed").as_secs();
    let present = ping_bt_mac(mac);
    return ScanReceipt {
      mac: mac.clone(),
      epoch_s: epoch_s,
      present: present,
    };
  }
}

// Unchanging global data
const SCAN_HIST_COUNT: usize = 6000;
const SECS_OK_TIME: u64 = 2 * 60; // Number of minutes to search for valid people
const LISTEN_ADDR: &'static str = "0.0.0.0:8080";
const PEOPLE_FILE: &'static str = "./present_map.json";

lazy_static! { // Global but complex data
  static ref ALL_PEOPLE: Mutex<Vec<Person>> = Mutex::new(vec![]);
  static ref ALL_SCANS: Mutex<Vec<ScanReceipt>> = Mutex::new(vec![]);
  static ref ALL_UNKNOWN_SCANS: Mutex<Vec<ScanReceipt>> = Mutex::new(vec![]);
}

fn main() { // Approx 100m
  let mut f = File::open(PEOPLE_FILE).expect("file not found");
  let mut contents = String::new();
  f.read_to_string(&mut contents).expect("something went wrong reading the file");
  let people: Vec<Person> = serde_json::from_str(contents.as_str()).unwrap();
  
  match ALL_PEOPLE.lock() {
    Ok(mut all_people_locked) => {
      for person in &people[..] {
        all_people_locked.push(person.clone());
      }
    }
    _ => return
  }
  
  { // Get sudo pw
    Command::new("sudo") // Runs ~ every 3 seconds
        .args(&["printf", ""])
        .output()
        .unwrap();
  }
  
  let scanning_child = thread::spawn(|| { scanning_thread(); });
  let unknown_scanning_child = thread::spawn(|| { unknown_scanning_thread(); });
  let webserver_child = thread::spawn(|| { webserver_thread();  });
  let spawn_ngrok = thread::spawn(|| { ngrok_thread(); });
  
  { // Exit when everyone else is finished
    scanning_child.join().unwrap();
    unknown_scanning_child.join().unwrap();
    webserver_child.join().unwrap();
    spawn_ngrok.join().unwrap();
  }
}

fn ngrok_thread() {
  Command::new("pkill").args(&["ngrok"]).output().unwrap();
  thread::sleep(Duration::from_millis(400));
  Command::new("ngrok").args(&["http", "8080"])
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn().unwrap();
  thread::sleep(Duration::from_millis(400));
  let mut url = cmd_out(Command::new("sh").args(&["-c",
    "curl --silent http://127.0.0.1:4040/api/tunnels | jq '.\"tunnels\"[0].\"public_url\"' | tr -d '\"' | sed 's/tcp:\\/\\///g'"
  ]));
  while format!("{}", url) == "null" {
    thread::sleep(Duration::from_millis(200));
    url = cmd_out(Command::new("sh").args(&["-c",
      "curl --silent http://127.0.0.1:4040/api/tunnels | jq '.\"tunnels\"[0].\"public_url\"' | tr -d '\"' | sed 's/tcp:\\/\\///g'"
    ]));
  }
  println!("Ngrok URL = {}", url);
  set_qr_code(&format!("{}/mobile.html", url));
}

fn scanning_thread() {
  // Just scans everything, pushes results into ALL_SCANS
  loop {
    let our_all_people = ALL_PEOPLE.lock().unwrap().clone();
    // People add/deletion will have to wait between scans (likely ~5-10 secs)
    let mut all_people_scan_threads: Vec<thread::JoinHandle<()>> = vec![];
    
    for person in our_all_people {
      all_people_scan_threads.push( thread::spawn(move || {
        // One person's thread
        let scan_result = person.scan();
        match ALL_SCANS.lock() {
          Ok(mut all_scans_locked) => {
            all_scans_locked.push(scan_result);
            all_scans_locked.truncate(SCAN_HIST_COUNT);
          }
          _ => {}
        }
      }) );
    }
    
    for thread in all_people_scan_threads {
      thread.join().unwrap();
    }
  }
}

fn unknown_scanning_thread() {
  // Scans everything everything.
  loop {
    // Scan
    let mut this_iter: Vec<ScanReceipt> = vec![];
    let epoch_s = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time.exe has failed").as_secs();
    
    let raw_stdout = Command::new("sudo") // Runs ~ every 3 seconds
            .args(&["timeout", "-s", "SIGINT", "3s", "hcitool", "lescan", "--duplicates"])
            .output()
            .unwrap()
            .stdout;
    let stdout_str = String::from_utf8(raw_stdout).unwrap();
    
    for line in stdout_str.lines() {
      let mac_addr = line.split(" ").next().unwrap();
      if ! mac_addr.contains(':') { continue; }
      
      this_iter.push(ScanReceipt {
        mac: mac_addr.to_string().trim().to_string(),
        epoch_s: epoch_s,
        present: true,
      });
    }
    
    // Push results
    match ALL_UNKNOWN_SCANS.lock() {
      Ok(mut all_unknown_lock) => {
        for result in this_iter {
          let mut we_know = false;
          for known in all_unknown_lock.iter() {
            if known.mac == result.mac { we_know = true; break; }
          }
          if !we_know {
            all_unknown_lock.push(result);
            all_unknown_lock.truncate(200); // More conservative
          }
        }
      }
      _ => { }
    }
  }
}

fn webserver_thread() {
  let server = Server::http(LISTEN_ADDR).unwrap();
  println!("HTTP Server Listening on {}", LISTEN_ADDR);
  
  for request in server.incoming_requests() {
    handle_request(request);
  }
}

fn handle_request(request: Request) {
  //* Debugging
  println!("REQUEST method: {:?}, url: {:?}, headers: {:?}",
      request.method(),
      request.url(),
      "", //request.headers()
  );
  
  match request.url() {
    "/" | "/index.html" => {
      serve_file(request);
    }
    "/status.html" => {
      serve_status(request);
    }
    "/roster.csv" => {
      serve_csv(request);
    }
    "/post-new" => {
      gobble_new_person(request);
    }
    _ => {
      serve_file(request);
    }
  }
}

fn ping_bt_mac(mac: &String) -> bool { // True if ping went through (device is ping-able)
  let raw_stdout = Command::new("sudo")
            .args(&["l2ping", "-c", "2", "-t", "1", mac.as_str()])
            .output()
            .unwrap()
            .stdout;
  let stdout_str = String::from_utf8(raw_stdout).unwrap();
  //println!("{}", stdout_str);
  return stdout_str.contains("bytes from");
}

fn person_existed_since(p: &Person, oldest_epoch_s: u64) -> bool {
  match ALL_SCANS.lock() {
    Ok(all_scans_locked) => {
      for scan_result in &all_scans_locked[..] {
        if scan_result.mac == p.mac && scan_result.present && scan_result.epoch_s > oldest_epoch_s {
          return true;
        }
      }
    }
    _ => { }
  }
  match ALL_UNKNOWN_SCANS.lock() {
    Ok(all_unknown_lock) => {
      for scan_result in &all_unknown_lock[..] {
        if scan_result.mac == p.mac && scan_result.present && scan_result.epoch_s > oldest_epoch_s {
          return true;
        }
      }
    }
    _ => { }
  }
  return false;
}

fn save_people() {
  match ALL_PEOPLE.lock() {
    Ok(all_people_locked) => {
      let mut s = String::new();
      s += "[";
      for person in &all_people_locked[..] {
        s += "\n";
        s += serde_json::to_string(&person).unwrap().as_str();
        s += ",";
      }
      s.pop(); // Remove last ','
      s += "\n]";
      let mut f = File::create(PEOPLE_FILE).expect("Unable to create file");
      f.write_all(s.as_bytes()).expect("Unable to write data");
    }
    _ => { }
  }
}

fn cmd_out(cmd: &mut Command) -> String {
  return String::from( std::str::from_utf8(&cmd.output().unwrap().stdout).unwrap().trim() );
}

fn set_qr_code(val: &String) { // sets value in ./www/qr.png
  Command::new("qrencode")
      .args(&["-o", "./www/qr.png", "-s", "10", val.as_str()])
      .output()
      .unwrap();
}

fn gobble_new_person(mut request: Request) {
  let mut content = String::new();
  request.as_reader().read_to_string(&mut content).unwrap();
  
  let double_iterator = url::form_urlencoded::parse(&content.into_bytes());
  let mut p = Person{
    name:  String::new(),
    uin:   String::new(),
    email: String::new(),
    mac:   String::new(),
  };
  for (key, val) in double_iterator {
    match key.as_str() {
      "name" => {
        p.name = {
          let mut sanitized_name = String::new();
          for c in val.chars() {
            match c {
              'a' ... 'z' | 'A' ... 'Z' | '1' ... '9' | '0' | ' ' | '-' | '_' => {
                sanitized_name.push(c)
              },
              _ => {}
            }
          }
          sanitized_name
        }
      },
      "uin" => p.uin = val,
      "email" => p.email = val,
      "mac" => p.mac = val,
      _ => { }
    }
  }
  
  match ALL_PEOPLE.lock() {
    Ok(mut all_people_locked) => {
      all_people_locked.push(p.clone());
    }
    _ => { }
  }
  save_people();
  
  serve_404(request);
}

fn serve_status(request: Request) {
  let mut headers: Vec<Header> = Vec::new();
  headers.push(Header::from_bytes(&"Content-Type"[..], &"text/html; charset=utf-8"[..]).unwrap());
  let mut response_str = String::new();
  // Page refreshes every 5 seconds
  response_str += "<html><head><meta http-equiv=\"refresh\" content=\"6\"><link rel=\"stylesheet\" href=\"/style.css\"></head><body>";
  response_str += "<ul>";
  let x_minutes_ago = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time.exe has failed")
                        .as_secs() - 
                        (SECS_OK_TIME); // SECS_OK_TIME secs ago
  
  match ALL_PEOPLE.lock() {
      Ok(all_people_locked) => {
        for person in &all_people_locked[..] {
          let last_status = person_existed_since(person, x_minutes_ago);
          response_str.push_str(
            &format!("<li class=\"{}\">{}</li>", if last_status { "present" } else { "absent" }, person.name)
          );
        }
      },
      _ => { }
  }
  response_str += "</ul><ul id=\"unknownMACs\">";
  // Dump all unknown BT MACs we see
  match ALL_UNKNOWN_SCANS.lock() {
    Ok(all_unknowns_locked) => {
      let now_epoch_s = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time.exe has failed").as_secs();
      for unknown_device in all_unknowns_locked.iter() {
        if now_epoch_s - unknown_device.epoch_s > SECS_OK_TIME { continue; } // Ignore people we haven't seen in SECS_OK_TIME
        response_str.push_str(
          &format!("<li class=\"unknown\">{}</li>", unknown_device.mac)
        );
      }
    }
    _ => { response_str += "ERR"; }
  }
  response_str += "</ul></body></html>";
  let response = Response::new(StatusCode::from(200), headers, response_str.as_bytes(), Some(response_str.len()), None);
  let _ = request.respond(response);
}

fn serve_csv(request: Request) {
  let mut headers: Vec<Header> = Vec::new();
  headers.push(Header::from_bytes(&"Content-Type"[..], &"text/csv; charset=utf-8"[..]).unwrap());
  let mut response_str = String::new();
  response_str += "name,uin,email,status,\n";
  let x_minutes_ago = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("Time.exe has failed")
                        .as_secs() - 
                        (SECS_OK_TIME); // SECS_OK_TIME secs ago
  
  match ALL_PEOPLE.lock() {
      Ok(all_people_locked) => {
        for person in &all_people_locked[..] {
          let last_status = person_existed_since(person, x_minutes_ago);
          response_str.push_str(
            &format!("{},{},{},{},\n", person.name, person.uin, person.email, if last_status { "present" } else { "absent" })
          );
        }
      },
      _ => { }
  }
  let response = Response::new(StatusCode::from(200), headers, response_str.as_bytes(), Some(response_str.len()), None);
  let _ = request.respond(response);
}

fn serve_file(request: Request) { // Serves file if under ./www/
  let www_path_concat = format!("{}/www/", cmd_out(&mut Command::new("pwd")));
  let possible_www_path_concat = format!("{}{}", www_path_concat, match request.url() {
    "/" => "/index.html",
    path => path,
  });
  match Path::new(&possible_www_path_concat[..]).canonicalize() {
    Ok(possible_www_path) => {
      let is_under_www_dir = possible_www_path.to_str().unwrap().find(&www_path_concat[..]).unwrap() == 0;
      if is_under_www_dir && possible_www_path.exists() {
        match fs::File::open(Path::new(possible_www_path.to_str().unwrap())) {
          Ok(file) => {
            let mut response = Response::from_file(file);
            let _ = request.respond(response);
          }
          Err(_) => {
            serve_404(request);
          }
        }
      }
      else {
        serve_404(request);
      }
    },
    Err(_) => {
      serve_404(request);
    }
  };
}

fn serve_404(request: Request) {
  let mut headers: Vec<Header> = Vec::new();
  headers.push(Header::from_bytes(&"Content-Type"[..], &"text/html; charset=utf-8"[..]).unwrap());
  headers.push(Header::from_bytes(&"Location"[..], &"/"[..]).unwrap());
  let response_str = "<h1>Redirecting...</h1>".to_string();
  let response = Response::new(StatusCode::from(307), headers, response_str.as_bytes(), Some(response_str.len()), None);
  let _ = request.respond(response);
}