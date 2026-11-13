//! `dns-fallback`: where to find a name the system cannot resolve, as `name=address` pairs. For our
//! public name on an intranet with no route out: no DNS answers for it there, and its server is
//! reachable at a private address only. Only the lookup changes: requests, SNI and the certificate
//! check still go by the name, so callers use it only where the certificate is checked, and a host
//! at that address on someone else's network cannot pass for the server.
//!
//! WebSocket connections and the HTTP clients both look names up here. Whichever of them finds the
//! system failing first marks the name, which spares the others the wait for a while.

use crate::{
    config::{keys::OPTION_DNS_FALLBACK, Config},
    log,
};
use std::{
    collections::HashMap,
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::Mutex,
    time::Duration,
};
use tokio::{
    net::TcpStream,
    time::{timeout, Instant},
};

/// How long the system may take to resolve a covered name. On an intranet with no route out its
/// queries mostly time out, and it takes 10 s or more to give up on them.
const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
/// After the system failed a covered name, how long its fallback is used without asking again.
const FAILED_FOR: Duration = Duration::from_secs(60);

lazy_static::lazy_static! {
    /// What the system last made of each covered name, in this process: whether it resolved
    /// it, and when.
    static ref VERDICTS: Mutex<HashMap<String, (bool, Instant)>> = Default::default();
}

/// The `dns-fallback` option: names, lowercased, and their addresses.
#[derive(Debug, Default)]
pub struct Fallback(HashMap<String, Vec<IpAddr>>);

impl Fallback {
    pub fn from_config() -> Self {
        Self::parse(&Config::get_option(OPTION_DNS_FALLBACK))
    }

    /// `name=address` pairs separated by commas or whitespace. A name given twice gets both
    /// addresses. Anything else is logged and left out.
    pub fn parse(value: &str) -> Self {
        let mut names: HashMap<String, Vec<IpAddr>> = HashMap::new();
        let pairs = value.split(|c: char| c == ',' || c.is_whitespace());
        for pair in pairs.filter(|pair| !pair.is_empty()) {
            let parsed = pair.split_once('=').and_then(|(name, ip)| {
                let name = normalize(name);
                let ip = ip.parse::<IpAddr>().ok()?;
                (!name.is_empty()).then_some((name, ip))
            });
            match parsed {
                Some((name, ip)) => names.entry(name).or_default().push(ip),
                None => log::warn!("dns-fallback: {pair:?} is not name=address, left out"),
            }
        }
        Self(names)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn covers(&self, host: &str) -> bool {
        self.0.contains_key(&normalize(host))
    }

    /// Whether the system failed to resolve covered `host` when last asked, within `FAILED_FOR`:
    /// what a lookup would fall back for right now, without making one. Other programs on this
    /// machine, a browser say, cannot resolve it either then.
    pub fn unresolved(&self, host: &str) -> bool {
        let name = normalize(host);
        let verdict = VERDICTS.lock().unwrap().get(&name).copied();
        self.0.contains_key(&name)
            && matches!(verdict, Some((false, at)) if at.elapsed() < FAILED_FOR)
    }

    /// `host`'s addresses as the system resolves it. For a covered name, the fallback instead when
    /// the system fails within `LOOKUP_TIMEOUT` or has failed in the last `FAILED_FOR`. Port 0 is
    /// fine for callers that set the port themselves.
    pub async fn lookup(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let system = || async move { Ok(tokio::net::lookup_host((host, port)).await?.collect()) };
        let name = normalize(host);
        match self.0.get(&name) {
            None => system().await,
            Some(ips) => Ok(lookup_with(&name, ips, port, system).await),
        }
    }

    /// A TCP connection to the first of `host`'s addresses (see `lookup`) that accepts one.
    pub async fn connect(&self, host: &str, port: u16) -> io::Result<TcpStream> {
        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
        for addr in self.lookup(host, port).await? {
            match TcpStream::connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(err) => last = err,
            }
        }
        Err(last)
    }
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The addresses of covered `name`, `system` being the system's lookup of it.
async fn lookup_with<F, Fut>(
    name: &str,
    fallback: &[IpAddr],
    port: u16,
    system: F,
) -> Vec<SocketAddr>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = io::Result<Vec<SocketAddr>>>,
{
    let fallback = || {
        fallback
            .iter()
            .map(|ip| SocketAddr::new(*ip, port))
            .collect()
    };
    let started = Instant::now();
    let verdict = VERDICTS.lock().unwrap().get(name).copied();
    if matches!(verdict, Some((false, at)) if at.elapsed() < FAILED_FOR) {
        return fallback();
    }
    let why = match timeout(LOOKUP_TIMEOUT, system()).await {
        Ok(Ok(addrs)) if !addrs.is_empty() => {
            let resolved = (true, Instant::now());
            let before = VERDICTS.lock().unwrap().insert(name.to_owned(), resolved);
            if matches!(before, Some((false, _))) {
                log::info!("{name} resolves again: dns-fallback no longer used for it");
            }
            return addrs;
        }
        Ok(Ok(_)) => "no address".to_owned(),
        Ok(Err(err)) => err.to_string(),
        Err(_) => format!("no answer in {LOOKUP_TIMEOUT:?}"),
    };
    let mut verdicts = VERDICTS.lock().unwrap();
    match verdicts.get(name) {
        // Another lookup resolved it while this one was failing: its word is the later one.
        Some((true, at)) if *at >= started => {}
        before => {
            // Logged on failing anew, not on each lookup while it lasts.
            if !matches!(before, Some((false, _))) {
                log::info!(
                    "The system cannot resolve {name} ({why}): using its dns-fallback address"
                );
            }
            verdicts.insert(name.to_owned(), (false, Instant::now()));
        }
    }
    fallback()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn pairs_parse_into_names_and_addresses() {
        let fallback = Fallback::parse(
            " App.Example.com.=10.0.0.5, app.example.com=10.0.0.6\n\
             v6.example=fd00::1  bad x= =10.0.0.7 y=not-an-ip ",
        );
        assert_eq!(fallback.0.len(), 2);
        assert_eq!(
            fallback.0["app.example.com"],
            [ip("10.0.0.5"), ip("10.0.0.6")]
        );
        assert_eq!(fallback.0["v6.example"], [ip("fd00::1")]);
        assert!(fallback.covers("APP.example.COM."));
        assert!(!fallback.covers("example.com"));
        assert!(Fallback::parse("").is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn the_fallback_stands_in_while_the_system_fails() {
        let (name, ips) = ("fails.test", [ip("10.0.0.5")]);
        let asked = AtomicUsize::new(0);
        let failing = || {
            asked.fetch_add(1, SeqCst);
            async { Err(io::Error::other("no DNS")) }
        };
        let fallback = Fallback::parse("fails.test=10.0.0.5, other.test=10.0.0.6");
        assert!(!fallback.unresolved(name));
        assert_eq!(
            lookup_with(name, &ips, 4443, failing).await,
            [addr("10.0.0.5:4443")]
        );
        // Known unresolved now: this name alone, and only as one the option covers.
        assert!(fallback.unresolved("Fails.Test."));
        assert!(!fallback.unresolved("other.test"));
        assert!(!Fallback::parse("").unresolved(name));
        // Within FAILED_FOR the system is not asked again.
        tokio::time::advance(FAILED_FOR - Duration::from_secs(1)).await;
        assert_eq!(
            lookup_with(name, &ips, 4443, failing).await,
            [addr("10.0.0.5:4443")]
        );
        assert_eq!(asked.load(SeqCst), 1);
        // After it, it is, and its answer wins and clears the mark.
        tokio::time::advance(Duration::from_secs(2)).await;
        let public = addr("203.0.113.9:4443");
        let answering = || async move { Ok(vec![public]) };
        assert_eq!(lookup_with(name, &ips, 4443, answering).await, [public]);
        assert!(matches!(
            VERDICTS.lock().unwrap().get(name),
            Some((true, _))
        ));
        assert!(!fallback.unresolved(name));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_overtaken_by_an_answer_does_not_mark_the_name() {
        let (name, ips) = ("overtaken.test", [ip("10.0.0.5")]);
        let public = addr("203.0.113.9:443");
        // Fails after a second, by when another lookup has resolved the name.
        let failing_late = || async {
            tokio::time::sleep(Duration::from_secs(1)).await;
            Err(io::Error::other("no DNS"))
        };
        let (failed, answered) = tokio::join!(
            lookup_with(name, &ips, 443, failing_late),
            lookup_with(name, &ips, 443, || async move { Ok(vec![public]) }),
        );
        assert_eq!(
            (failed, answered),
            (vec![addr("10.0.0.5:443")], vec![public])
        );
        // So the next lookup asks the system again instead of taking the fallback.
        let asked = AtomicUsize::new(0);
        let answering = || {
            asked.fetch_add(1, SeqCst);
            async move { Ok(vec![public]) }
        };
        assert_eq!(lookup_with(name, &ips, 443, answering).await, [public]);
        assert_eq!(asked.load(SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_or_empty_answer_counts_as_failing() {
        let ips = [ip("10.0.0.5")];
        let slow = || async {
            tokio::time::sleep(LOOKUP_TIMEOUT * 4).await;
            Ok(vec![addr("203.0.113.9:0")])
        };
        let started = Instant::now();
        assert_eq!(
            lookup_with("slow.test", &ips, 443, slow).await,
            [addr("10.0.0.5:443")]
        );
        assert_eq!(started.elapsed(), LOOKUP_TIMEOUT);
        let empty = || async { Ok(vec![]) };
        assert_eq!(
            lookup_with("empty.test", &ips, 443, empty).await,
            [addr("10.0.0.5:443")]
        );
    }

    #[tokio::test]
    async fn names_not_covered_are_the_system_s() {
        let fallback = Fallback::parse("app.example.com=10.0.0.5");
        let addrs = fallback.lookup("127.0.0.1", 80).await.unwrap();
        assert_eq!(addrs, [addr("127.0.0.1:80")]);
    }

    #[tokio::test]
    async fn connect_reaches_the_fallback_address() {
        // `.invalid` never resolves (RFC 6761), unless a TUN proxy answers every name.
        let name = "dns-fallback-connect.invalid";
        if tokio::net::lookup_host((name, 0)).await.is_ok() {
            eprintln!("skipped: this machine's resolver answers for {name}");
            return;
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let fallback = Fallback::parse(&format!("{name}=127.0.0.1"));
        let stream = fallback.connect(name, port).await.unwrap();
        assert_eq!(
            stream.peer_addr().unwrap(),
            addr(&format!("127.0.0.1:{port}"))
        );
    }
}
