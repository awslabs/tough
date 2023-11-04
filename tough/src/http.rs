//! The `http` module provides `HttpTransport` which enables `Repository` objects to be
//! loaded over HTTP
use crate::transport::TransportStream;
use crate::{Transport, TransportError, TransportErrorKind};
use async_trait::async_trait;
use futures::{FutureExt, StreamExt};
use futures_core::future::BoxFuture;
use futures_core::stream::BoxStream;
use futures_core::Stream;
use log::trace;
use reqwest::header::{self, HeaderValue, ACCEPT_RANGES};
use reqwest::{Client, ClientBuilder, Request, Response};
use reqwest::{Error, Method};
use snafu::ResultExt;
use snafu::Snafu;
use std::cmp::Ordering;
use std::pin::Pin;
use std::task::Poll;
use std::time::Duration;
use url::Url;

/// A builder for [`HttpTransport`] which allows settings customization.
///
/// # Example
///
/// ```
/// # use tough::HttpTransportBuilder;
/// let http_transport = HttpTransportBuilder::new()
/// .tries(3)
/// .backoff_factor(1.5)
/// .build();
/// ```
///
/// See [`HttpTransport`] for proxy support and other behavior details.
///
#[derive(Clone, Copy, Debug)]
pub struct HttpTransportBuilder {
    timeout: Duration,
    connect_timeout: Duration,
    tries: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
    backoff_factor: f32,
}

impl Default for HttpTransportBuilder {
    fn default() -> Self {
        Self {
            timeout: std::time::Duration::from_secs(30),
            connect_timeout: std::time::Duration::from_secs(10),
            /// try / 100ms / try / 150ms / try / 225ms / try
            tries: 4,
            initial_backoff: std::time::Duration::from_millis(100),
            max_backoff: std::time::Duration::from_secs(1),
            backoff_factor: 1.5,
        }
    }
}

impl HttpTransportBuilder {
    /// Create a new `HttpTransportBuilder` with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a timeout for the complete fetch operation.
    #[must_use]
    pub fn timeout(mut self, value: Duration) -> Self {
        self.timeout = value;
        self
    }

    /// Set a timeout for only the connect phase.
    #[must_use]
    pub fn connect_timeout(mut self, value: Duration) -> Self {
        self.connect_timeout = value;
        self
    }

    /// Set the total number of times we will try the fetch operation (in case of retryable
    /// failures).
    #[must_use]
    pub fn tries(mut self, value: u32) -> Self {
        self.tries = value;
        self
    }

    /// Set the pause duration between the first and second try.
    #[must_use]
    pub fn initial_backoff(mut self, value: Duration) -> Self {
        self.initial_backoff = value;
        self
    }

    /// Set the maximum duration of a pause between retries.
    #[must_use]
    pub fn max_backoff(mut self, value: Duration) -> Self {
        self.max_backoff = value;
        self
    }

    /// Set the exponential backoff factor, the factor by which the pause time will increase after
    /// each try until reaching `max_backoff`.
    #[must_use]
    pub fn backoff_factor(mut self, value: f32) -> Self {
        self.backoff_factor = value;
        self
    }

    /// Construct an [`HttpTransport`] transport from this builder's settings.
    pub fn build(self) -> HttpTransport {
        HttpTransport { settings: self }
    }
}

/// A [`Transport`] over HTTP with retry logic. Use the [`HttpTransportBuilder`] to construct a
/// custom `HttpTransport`, or use `HttpTransport::default()`.
///
/// This transport returns `FileNotFound` for the following HTTP response codes:
/// - 403: Forbidden. (Some services return this code when a file does not exist.)
/// - 404: Not Found.
/// - 410: Gone.
///
/// # Proxy Support
///
/// To use the `HttpTransport` with a proxy, specify the `HTTPS_PROXY` environment variable.
/// The transport will also respect the `NO_PROXY` environment variable.
///
#[derive(Clone, Copy, Debug, Default)]
pub struct HttpTransport {
    settings: HttpTransportBuilder,
}

/// Implement the `tough` `Transport` trait for `HttpRetryTransport`
#[async_trait]
impl Transport for HttpTransport {
    /// Send a GET request to the URL. The returned `TransportStream` will retry as necessary per
    /// the `ClientSettings`.
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let r = RetryState::new(self.settings.initial_backoff);
        Ok(fetch_with_retries(r, &self.settings, &url).boxed())
    }
}

enum RequestState {
    /// A response is streaming.
    Streaming(BoxStream<'static, reqwest::Result<bytes::Bytes>>),
    /// A request is pending.
    Pending(BoxFuture<'static, reqwest::Result<reqwest::Response>>),
    /// No ongoing request.
    None,
}

impl std::fmt::Debug for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestState::Streaming(_) => f.write_str("Streaming"),
            RequestState::Pending(_) => f.write_str("Executing"),
            RequestState::None => f.write_str("None"),
        }
    }
}

#[derive(Debug)]
struct RetryStream {
    retry_state: RetryState,
    settings: HttpTransportBuilder,
    url: Url,
    request: RequestState,
    done: bool,
    has_range_support: bool,
}

impl Stream for RetryStream {
    type Item = Result<bytes::Bytes, TransportError>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }

        self.poll_streaming(cx)
            .or_else(|| self.poll_executing(cx))
            .unwrap_or_else(|| match self.poll_new_request(cx) {
                Ok(poll) => poll,
                Err(e) => Poll::Ready(Some(Err((self.url.clone(), e).into()))),
            })
    }
}

impl RetryStream {
    fn poll_err<E>(&mut self, error: E) -> Poll<Option<Result<bytes::Bytes, TransportError>>>
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        self.done = true;
        Poll::Ready(Some(Err(TransportError::new_with_cause(
            TransportErrorKind::Other,
            self.url.clone(),
            error,
        ))))
    }

    fn poll_streaming(
        self: &mut Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Option<std::task::Poll<Option<<Self as Stream>::Item>>> {
        let RequestState::Streaming(stream) = &mut self.request else {
            return None;
        };
        let next = stream.as_mut().poll_next(cx);
        match next {
            // Success. End stream.
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            // New chunk received, keep track of position for potential recovery.
            Poll::Ready(Some(Ok(data))) => {
                self.retry_state.next_byte += data.len();
                Poll::Ready(Some(Ok(data)))
            }
            // Error while streaming the response body. Try to recover.
            Poll::Ready(Some(Err(err))) => match ErrorClass::from(err) {
                ErrorClass::Fatal(e) => self.poll_err(e),
                ErrorClass::FileNotFound(_) => unreachable!("streaming the response body already"),
                ErrorClass::Retryable(e) => {
                    if self.may_retry() {
                        match self.poll_new_request(cx) {
                            Ok(poll) => poll,
                            Err(_) => self.poll_err(e),
                        }
                    } else {
                        self.poll_err(e)
                    }
                }
            },
            Poll::Pending => Poll::Pending,
        }
        .into()
    }

    fn poll_executing(
        self: &mut Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Option<std::task::Poll<Option<<Self as Stream>::Item>>> {
        let RequestState::Pending(request) = &mut self.request else {
            return None;
        };
        match request.as_mut().poll(cx) {
            Poll::Ready(response) => {
                let http_result: HttpResult = response.into();
                match http_result {
                    HttpResult::Ok(response) => {
                        trace!("{:?} - returning from successful fetch", self.retry_state);
                        if let Some(ranges) = response.headers().get(ACCEPT_RANGES) {
                            if let Ok(val) = ranges.to_str() {
                                if val.contains("bytes") {
                                    self.has_range_support = true;
                                }
                            }
                        }
                        self.request = RequestState::Streaming(response.bytes_stream().boxed());
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    HttpResult::Err(ErrorClass::Fatal(e)) => {
                        trace!(
                            "{:?} - returning fatal error from fetch: {}",
                            self.retry_state,
                            e
                        );
                        self.poll_err(e)
                    }
                    HttpResult::Err(ErrorClass::FileNotFound(e)) => {
                        trace!(
                            "{:?} - returning file not found from fetch: {}",
                            self.retry_state,
                            e
                        );
                        self.done = true;
                        Poll::Ready(Some(Err(TransportError::new_with_cause(
                            TransportErrorKind::FileNotFound,
                            self.url.clone(),
                            e,
                        ))))
                    }
                    HttpResult::Err(ErrorClass::Retryable(e)) => {
                        trace!("{:?} - retryable error: {}", self.retry_state, e);
                        if self.may_retry() {
                            match self.poll_new_request(cx) {
                                Ok(poll) => poll,
                                Err(_) => self.poll_err(e),
                            }
                        } else {
                            self.poll_err(e)
                        }
                    }
                }
            }
            Poll::Pending => Poll::Pending,
        }
        .into()
    }
    /// Check all criteria for a retry and account for it.
    fn may_retry(&mut self) -> bool {
        let tries_left = self
            .settings
            .tries
            .saturating_sub(self.retry_state.current_try);

        self.retry_state.increment(&self.settings);

        tries_left > 0 && (self.has_range_support || self.retry_state.next_byte == 0)
    }

    /// Move to `RequestState::Executing`.
    fn poll_new_request(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> Result<Poll<Option<Result<bytes::Bytes, TransportError>>>, HttpError> {
        // create a reqwest client
        let client = ClientBuilder::new()
            .timeout(self.settings.timeout)
            .connect_timeout(self.settings.connect_timeout)
            .build()
            .context(HttpClientSnafu)?;

        // build the request
        let request = build_request(&client, self.retry_state.next_byte, &self.url)?;

        let backoff = self.retry_state.wait;

        let delayed_request = async move {
            tokio::time::sleep(backoff).await;
            client.execute(request).await
        }
        .boxed();

        self.request = RequestState::Pending(delayed_request);

        // start polling the new request
        cx.waker().wake_by_ref();
        Ok(Poll::Pending)
    }
}

/// A private struct that serves as the retry counter.
#[derive(Clone, Debug)]
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
    /// Increments the count and the wait duration.
    fn increment(&mut self, settings: &HttpTransportBuilder) {
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
fn fetch_with_retries(r: RetryState, cs: &HttpTransportBuilder, url: &Url) -> RetryStream {
    trace!("beginning fetch for '{}'", url);

    RetryStream {
        retry_state: r,
        settings: *cs,
        url: url.clone(),
        request: RequestState::None,
        done: false,
        has_range_support: false,
    }
}

/// A newtype result for ergonomic conversions.
enum HttpResult {
    Ok(reqwest::Response),
    Err(ErrorClass),
}

/// Group reqwest errors into interesting cases.
/// Much of the complexity in the `fetch_with_retries` function is in deciphering the `Result`
/// we get from `reqwest::Client::execute`. Using this enum we categorize the states of the
/// `Result` into the categories that we need to understand.
enum ErrorClass {
    /// We got an `Error` (other than file-not-found) which we will not retry.
    Fatal(reqwest::Error),
    /// The file could not be found (HTTP status 403 or 404).
    FileNotFound(reqwest::Error),
    /// We received an `Error`, or we received an HTTP response code that we can retry.
    Retryable(reqwest::Error),
}

/// Takes the `Result` type from `reqwest::Client::execute`, and categorizes it into an
/// `HttpResult` variant.
impl From<Result<reqwest::Response, reqwest::Error>> for HttpResult {
    fn from(result: Result<Response, Error>) -> Self {
        match result {
            Ok(response) => {
                trace!("response received");
                // checks the status code of the response for errors
                parse_response_code(response)
            }
            Err(e) => Self::Err(e.into()),
        }
    }
}

/// Catergorize a `request::Error` into a `HttpResult` variant.
impl From<reqwest::Error> for ErrorClass {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            // a connection timeout occurred
            trace!("timeout error during fetch: {}", err);
            ErrorClass::Retryable(err)
        } else if err.is_request() {
            // an error occurred while sending the request
            trace!("error sending request during fetch: {}", err);
            ErrorClass::Retryable(err)
        } else {
            // the error is not from an HTTP status code or a timeout, retries will not succeed.
            // these appear to be internal, reqwest errors and are expected to be unlikely.
            trace!("internal reqwest error during fetch: {}", err);
            ErrorClass::Fatal(err)
        }
    }
}

/// Checks the HTTP response code and converts a non-successful response code to an error.
fn parse_response_code(response: reqwest::Response) -> HttpResult {
    match response.error_for_status() {
        Ok(ok) => {
            trace!("response is success");
            // http status code indicates success
            HttpResult::Ok(ok)
        }
        // http status is an error
        Err(err) => match err.status() {
            None => {
                // this shouldn't happen, we received this err from the err_for_status function,
                // so the error should have a status. we cannot consider this a retryable error.
                trace!("error is fatal (no status): {}", err);
                HttpResult::Err(ErrorClass::Fatal(err))
            }
            Some(status) if status.is_server_error() => {
                trace!("error is retryable: {}", err);
                HttpResult::Err(ErrorClass::Retryable(err))
            }
            Some(status) if matches!(status.as_u16(), 403 | 404 | 410) => {
                trace!("error is file not found: {}", err);
                HttpResult::Err(ErrorClass::FileNotFound(err))
            }
            Some(_) => {
                trace!("error is fatal (status): {}", err);
                HttpResult::Err(ErrorClass::Fatal(err))
            }
        },
    }
}

/// Builds a GET request. If `next_byte` is greater than zero, adds a byte range header to the request.
fn build_request(client: &Client, next_byte: usize, url: &Url) -> Result<Request, HttpError> {
    if next_byte == 0 {
        let request = client
            .request(Method::GET, url.as_str())
            .build()
            .context(RequestBuildSnafu)?;
        Ok(request)
    } else {
        let header_value_string = format!("bytes={next_byte}-");
        let header_value =
            HeaderValue::from_str(header_value_string.as_str()).context(InvalidHeaderSnafu {
                header_value: &header_value_string,
            })?;
        let request = client
            .request(Method::GET, url.as_str())
            .header(header::RANGE, header_value)
            .build()
            .context(RequestBuildSnafu)?;
        Ok(request)
    }
}

/// The error type for the HTTP transport module.
#[derive(Debug, Snafu)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum HttpError {
    #[snafu(display("A non-retryable error occurred: {}", source))]
    FetchFatal { source: reqwest::Error },

    #[snafu(display("File not found: {}", source))]
    FetchFileNotFound { source: reqwest::Error },

    #[snafu(display("Fetch failed after {} retries: {}", tries, source))]
    FetchNoMoreRetries { tries: u32, source: reqwest::Error },

    #[snafu(display("The HTTP client could not be built: {}", source))]
    HttpClient { source: reqwest::Error },

    #[snafu(display("Invalid header value '{}': {}", header_value, source))]
    InvalidHeader {
        header_value: String,
        source: reqwest::header::InvalidHeaderValue,
    },

    #[snafu(display("Unable to create HTTP request: {}", source))]
    RequestBuild { source: reqwest::Error },
}

/// Convert a URL `Url` and an `HttpError` into a `TransportError`
impl From<(Url, HttpError)> for TransportError {
    fn from((url, e): (Url, HttpError)) -> Self {
        match e {
            HttpError::FetchFileNotFound { .. } => {
                TransportError::new_with_cause(TransportErrorKind::FileNotFound, url, e)
            }
            _ => TransportError::new_with_cause(TransportErrorKind::Other, url, e),
        }
    }
}
