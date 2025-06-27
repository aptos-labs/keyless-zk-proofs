// Copyright © Aptos Foundation

use chrono::Utc;
use std::collections::HashMap;
use std::future::Future;
use std::sync::RwLock;
use std::time::Instant;
use tokio::task::futures::TaskLocalFuture;
use tokio::task_local;

task_local! {
    static LOGGER_CONTEXT: RwLock<HashMap<String, String>>;
}

pub fn run_with_empty_logger_context<F: Future>(
    f: F,
) -> TaskLocalFuture<RwLock<HashMap<String, String>>, F> {
    let obj = RwLock::new(HashMap::new());
    LOGGER_CONTEXT.scope(obj, f)
}

pub fn set_attr(key: impl ToString, val: impl ToString) {
    if tokio::runtime::Handle::try_current().is_ok() {
        LOGGER_CONTEXT.with(|ctxt| {
            let mut context = ctxt.write().unwrap();
            context.insert(key.to_string(), val.to_string());
        });
    }
}

pub fn unset_attr(key: impl ToString) {
    if tokio::runtime::Handle::try_current().is_ok() {
        LOGGER_CONTEXT.with(|ctxt| {
            let mut context = ctxt.write().unwrap();
            context.remove(&key.to_string());
        });
    }
}

pub fn info(message: impl ToString) {
    emit("INFO".to_string(), message);
}

pub fn warn(message: impl ToString) {
    emit("WARN".to_string(), message);
}

pub fn error(message: impl ToString) {
    emit("ERROR".to_string(), message);
}

pub struct Span {
    name: String,
    attrs: HashMap<String, String>,
    start_time: Instant,
}

impl Drop for Span {
    fn drop(&mut self) {
        let time_elapsed = self.start_time.elapsed();
        set_attr("milliseconds_elapsed", time_elapsed.as_millis().to_string());
        info(format!("Leaving span {}.", self.name));
        unset_attr("milliseconds_elapsed");
        for k in self.attrs.keys() {
            unset_attr(k);
        }
        unset_attr(&self.name);
    }
}

impl Span {
    fn new(name: impl ToString, extra_attrs: HashMap<String, String>) -> Self {
        let name = name.to_string();
        set_attr(&name, "1");
        for (k, v) in extra_attrs.iter() {
            set_attr(k, v);
        }
        info(format!("Entering span {}.", name));
        Self {
            name,
            attrs: extra_attrs,
            start_time: Instant::now(),
        }
    }
}

pub fn new_span(name: impl ToString) -> Span {
    new_span_extra_attrs(name, HashMap::new())
}

pub fn new_span_extra_attrs(name: impl ToString, extra_attrs: HashMap<&str, String>) -> Span {
    Span::new(
        name,
        extra_attrs
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
    )
}

fn emit(level: impl ToString, message: impl ToString) {
    if tokio::runtime::Handle::try_current().is_ok() {
        LOGGER_CONTEXT.with(|ctxt| {
            let mut context = { ctxt.read().unwrap().clone() };
            context.insert("level".to_string(), level.to_string());
            context.insert(
                "timestamp".to_string(),
                Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            );
            context.insert("message".to_string(), message.to_string());
            println!("{}", serde_json::to_string(&context).unwrap());
        })
    }
}
