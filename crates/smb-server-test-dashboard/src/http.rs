//! A minimal blocking HTTP/1.1 request handler covering the routes the
//! dashboard needs: the static page and two read-only JSON endpoints.

use crate::{csv, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;

/// The single-page dashboard, embedded so the binary is self-contained.
const INDEX_HTML: &str = include_str!("index.html");

/// HTTP status codes used by the dashboard's read-only routes.
const HTTP_OK: u16 = 200;
const HTTP_NOT_FOUND: u16 = 404;
const HTTP_METHOD_NOT_ALLOWED: u16 = 405;

/// Read the request line, route it, and write the response.
pub fn handle_connection(stream: TcpStream, csv_path: &Path) {
    let mut reader = BufReader::new(stream);
    let Some((method, target)) = read_request_line(&mut reader) else {
        return;
    };
    drain_headers(&mut reader);
    let stream = reader.get_mut();

    if method != "GET" {
        respond(stream, HTTP_METHOD_NOT_ALLOWED, "text/plain", b"method not allowed");
        return;
    }
    route(stream, &target, csv_path);
}

fn read_request_line(reader: &mut BufReader<TcpStream>) -> Option<(String, String)> {
    let mut line = String::new();
    if reader.read_line(&mut line).ok()? == 0 {
        return None;
    }
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    Some((method, target))
}

/// Consume the rest of the request headers up to the blank line.
fn drain_headers(reader: &mut BufReader<TcpStream>) {
    let mut line = String::new();
    while let Ok(n) = reader.read_line(&mut line) {
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        line.clear();
    }
}

fn route(stream: &mut TcpStream, target: &str, csv_path: &Path) {
    let path = target.split('?').next().unwrap_or("/");
    match path {
        "/" | "/index.html" => respond(stream, HTTP_OK, "text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        "/api/status" => respond_json(stream, &status_json(csv_path)),
        "/api/tests" => respond_json(stream, &tests_json(csv_path)),
        "/healthz" => respond(stream, HTTP_OK, "text/plain", b"ok"),
        _ => respond(stream, HTTP_NOT_FOUND, "text/plain", b"not found"),
    }
}

fn status_json(csv_path: &Path) -> String {
    let rows = csv::load(csv_path);
    let summary = csv::summarize(&rows);
    json::status_body(&rows, &summary)
}

fn tests_json(csv_path: &Path) -> String {
    let rows = csv::load(csv_path);
    json::tests_body(&rows)
}

fn respond_json(stream: &mut TcpStream, body: &str) {
    respond(stream, HTTP_OK, "application/json; charset=utf-8", body.as_bytes());
}

/// Write a complete HTTP/1.1 response and close the connection.
fn respond(stream: &mut TcpStream, code: u16, content_type: &str, body: &[u8]) {
    let reason = match code {
        200 => "OK",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
    // Drain anything the client is still sending so the RST doesn't truncate us.
    let _ = stream.read(&mut [0u8; 0]);
}
