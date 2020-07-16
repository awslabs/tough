//! The `http` module provides `HttpTransport` which enables `Repository` objects to be
//! loaded over HTTP
use crate::error::{self, Error, Result};
use crate::Transport;
use log::{debug, error, trace};
use reqwest::blocking::{Client, ClientBuilder, Request, Response};
use reqwest::header::{self, HeaderValue, ACCEPT_RANGES};
use reqwest::Method;
use snafu::ResultExt;
use std::cmp::Ordering;
use std::io::Read;
use std::time::Duration;
use url::Url;

/// Settings for the HTTP client including retry strategy and timeouts.
#[derive(Clone, Copy, Debug)]
pub struct ClientSettings {
    /// Set a timeout for connect, read and write operations.
    pub timeout: Duration,
    /// Set a timeout for only the connect phase.
    pub connect_timeout: Duration,
    /// The total number of times we will try to get the response.
    pub tries: u32,
    /// The pause between the first and second try.
    pub initial_backoff: Duration,
    /// The maximum length of a pause between retries.
    pub max_backoff: Duration,
    /// The exponential backoff factor, the factor by which the pause time will increase after each
    /// try until reaching `max_backoff`.
    pub backoff_factor: f32,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
            /// try / 100ms / try / 150ms / try / 220ms / try
            tries: 4,
            initial_backoff: std::time::Duration::from_millis(100),
            max_backoff: std::time::Duration::from_secs(1),
            backoff_factor: 1.5,
        }
    }
}

/// An HTTP `Transport` with retry logic.
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpTransport {
    settings: ClientSettings,
}

impl HttpTransport {
    /// Create a new `HttpRetryTransport` with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new `HttpRetryTransport` with specific settings.
    pub fn from_settings(settings: ClientSettings) -> Self {
        Self { settings }
    }
}

/// Implement the `tough` `Transport` trait for `HttpRetryTransport`
impl Transport for HttpTransport {
    type Stream = RetryRead;
    type Error = Error;

    /// Send a GET request to the URL. Request will be retried per the `ClientSettings`. The
    /// returned `RetryRead` will also retry as necessary per the `ClientSettings`.
    fn fetch(&self, url: Url) -> Result<Self::Stream> {
        let mut r = RetryState::new(self.settings.initial_backoff);
        fetch_with_retries(&mut r, &self.settings, &url)
    }
}

/// This serves as a `Read`, but carries with it the necessary information to do retries.
#[derive(Debug)]
pub struct RetryRead {
    retry_state: RetryState,
    settings: ClientSettings,
    response: Response,
    url: Url,
}

impl Read for RetryRead {
    /// Read bytes into `buf`, retrying as necessary.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // retry loop
        loop {
            let retry_err = match self.response.read(buf) {
                Ok(sz) => {
                    self.retry_state.next_byte += sz;
                    return Ok(sz);
                }
                // store the error in `retry_err` to return later if there are no more retries
                Err(err) => err,
            };
            debug!("error during read of '{}': {:?}", self.url, retry_err);

            // increment the `retry_state` and fetch a new reader if retries are not exhausted
            if self.retry_state.current_try >= self.settings.tries - 1 {
                // we are out of retries, so return the last known error.
                return Err(retry_err);
            }
            self.retry_state.increment(&self.settings);
            // wait, then retry the request (with a range header).
            std::thread::sleep(self.retry_state.wait);
            if !self.supports_range() {
                // we cannot send a byte range request to this server, so return the error
                error!(
                    "an error occurred and we cannot retry because the server \
                    does not support range requests '{}': {:?}",
                    self.url, retry_err
                );
                return Err(retry_err);
            }
            let new_retry_read =
                fetch_with_retries(&mut self.retry_state, &self.settings, &self.url)?;
            // the new fetch succeeded so we need to replace our read object with the new one.
            self.response = new_retry_read.response;
        }
    }
}

impl RetryRead {
    /// Checks for the header `Accept-Ranges: bytes`
    fn supports_range(&self) -> bool {
        if let Some(ranges) = self.response.headers().get(ACCEPT_RANGES) {
            if let Ok(val) = ranges.to_str() {
                if val.contains("bytes") {
                    return true;
                }
            }
        }
        false
    }
}

/// A private struct that serves as the retry counter.
#[derive(Clone, Copy, Debug)]
struct RetryState {
    /// The current try we are on. First try is zero.
    current_try: u32,
    /// The amount that the we should sleep before the next retry.
    wait: Duration,
    /// The next byte that we should read. e.g. the last read byte + 1.
    next_byte: usize,
}

impl RetryState {
    fn new(initial_wait: Duration) -> Self {
        Self {
            current_try: 0,
            wait: initial_wait,
            next_byte: 0,
        }
    }
}

impl RetryState {
    /// Increments the count and the wait duration. Returns `true` if `current_try` is less than or
    /// equal to `tries` (i.e. if you should retry).
    fn increment(&mut self, settings: &ClientSettings) {
        if self.current_try > 0 {
            let new_wait = self.wait.mul_f32(settings.backoff_factor);
            match new_wait.cmp(&settings.max_backoff) {
                Ordering::Less => {
                    self.wait = new_wait;
                }
                Ordering::Greater => {
                    self.wait = settings.max_backoff;
                }
                Ordering::Equal => {}
            }
        }
        self.current_try += 1;
    }
}

/// Sends a `GET` request to the `url`. Retries the request as necessary per the `ClientSettings`.
fn fetch_with_retries(r: &mut RetryState, cs: &ClientSettings, url: &Url) -> Result<RetryRead> {
    trace!("beginning fetch for '{}'", url);
    // create a reqwest client
    let client = ClientBuilder::new()
        .timeout(cs.timeout)
        .connect_timeout(cs.connect_timeout)
        .build()
        .context(error::HttpClientBuild { url: url.clone() })?;
    // retry loop
    loop {
        // build the request
        let request = build_request(&client, r.next_byte, &url)?;

        // send the request and convert error status codes to an `Err`.
        let result = match client.execute(request) {
            Ok(response) => match response.error_for_status() {
                Ok(response) => Ok(response),
                Err(err) => Err(err),
            },
            Err(err) => Err(err),
        };

        // check the result, if it is a non-retryable error, return the error. if it is a retryable-
        // error, assign it to `retry_err`. if there is no error then return the read.
        let retry_err = match result {
            Ok(reqwest_read) => {
                return Ok(RetryRead {
                    retry_state: *r,
                    settings: *cs,
                    response: reqwest_read,
                    url: url.clone(),
                });
            }
            Err(err) => {
                // if it's a status code error other than 5XX, return the error
                if let Some(status) = err.status() {
                    if !status.is_success() && !status.is_server_error() {
                        return Err(err).context(error::HttpFetch { url: url.clone() });
                    }
                }
                // we will retry if possible, otherwise we will return this err.
                err
            }
        };

        // increment the retry state and continue trying unless we are out of tries
        if r.current_try >= cs.tries - 1 {
            return Err(retry_err).context(error::HttpRetries {
                url: url.clone(),
                tries: cs.tries,
            });
        }
        r.increment(&cs);
        std::thread::sleep(r.wait);
    }
}

fn build_request(client: &Client, next_byte: usize, url: &Url) -> Result<Request> {
    if next_byte == 0 {
        let request = client
            .request(Method::GET, url.as_str())
            .build()
            .context(error::HttpRequestBuild { url: url.clone() })?;
        Ok(request)
    } else {
        let header_value_string = format!("bytes={}-", next_byte);
        let header_value =
            HeaderValue::from_str(header_value_string.as_str()).context(error::HttpHeader {
                header_value: &header_value_string,
            })?;
        let request = client
            .request(Method::GET, url.as_str())
            .header(header::RANGE, header_value)
            .build()
            .context(error::HttpRequestBuild { url: url.clone() })?;
        Ok(request)
    }
}
