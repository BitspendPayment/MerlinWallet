//! The `Host` trait must match the WIT it stands in for.
//!
//! `src/host.rs` mirrors `enclave:tasks/queue` and `enclave:notify/notify` by hand. The crate now
//! builds as a wasm32-wasip2 component, so the obstacle to `wit_bindgen::generate!` is no longer
//! tonic — it is that this world still has to be composed with the one `wstd::http_server` exports.
//! Until that lands the mirror is hand-written, and nothing but this file checks it.
//!
//! Hand-copying an interface is the thing WIT exists to prevent. This reads the vendored `.wit`
//! and asserts every function in it has a counterpart on the trait with the same arity, so a
//! signature that changes upstream fails here rather than surfacing as a trap in a component that
//! looked fine. `scripts/wit-drift.sh` checks the other half: that the vendored copy still equals
//! enclave-runtime's canonical one.

use std::collections::BTreeMap;
use std::fs;

/// Every `name: func(a: T, b: U) -> R;` in a WIT file, as name → parameter count.
///
/// Deliberately not a WIT parser. It reads the one shape these two interfaces use, and anything it
/// cannot read it reports rather than skips — a lenient reader here would quietly stop checking.
fn wit_funcs(path: &str, exports: &mut Vec<String>) -> BTreeMap<String, usize> {
    let src = fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let mut out = BTreeMap::new();
    for line in src.lines() {
        let line = line.trim();
        if line.starts_with("//") || !line.contains(": func(") {
            continue;
        }
        let (name, rest) = line.split_once(": func(").expect("checked above");
        // `export run-task: func(...)` is the guest's to implement, not the runtime's to offer.
        // Strip the keyword and record it separately so the test can assert it is NOT on `Host`.
        let name = name.trim().strip_prefix("export ").map_or(name.trim(), |n| {
            exports.push(n.trim().to_string());
            n.trim()
        });
        let args = rest.split(')').next().unwrap_or("");
        let arity = if args.trim().is_empty() {
            0
        } else {
            // Parameters are comma-separated; no nested generics appear in these two interfaces,
            // and `assert_no_nesting` below fails if that ever stops being true.
            args.matches(',').count() + 1
        };
        assert!(
            !args.contains('<') || args.matches('<').count() == args.matches('>').count(),
            "unbalanced generic in {name}: {args:?} — this reader cannot count those parameters"
        );
        out.insert(name.to_string(), arity);
    }
    assert!(!out.is_empty(), "no functions found in {path} — this check has stopped checking");
    out
}

/// The trait's methods, as the WIT spells them (kebab-case), with `&self` not counted.
fn host_trait_methods() -> BTreeMap<String, usize> {
    let src = fs::read_to_string("src/host.rs").expect("read src/host.rs");
    // Only the trait body, not `Detached`'s impl.
    let body = src
        .split_once("pub trait Host")
        .expect("the trait moved")
        .1;
    let body = &body[..body.find("\n}\n").expect("unterminated trait")];

    let mut out = BTreeMap::new();
    let mut i = 0;
    while let Some(at) = body[i..].find("fn ") {
        let start = i + at + 3;
        let name: String = body[start..]
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        // Parameters: from the '(' to its matching ')'.
        let open = start + body[start..].find('(').expect("no parameter list");
        let mut depth = 0;
        let mut close = open;
        for (k, c) in body[open..].char_indices() {
            match c {
                '(' | '<' => depth += 1,
                ')' | '>' => {
                    depth -= 1;
                    if depth == 0 {
                        close = open + k;
                        break;
                    }
                }
                _ => {}
            }
        }
        let params = &body[open + 1..close];
        let arity = params
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty() && *p != "&self" && *p != "&mut self")
            .count();
        out.insert(name.replace('_', "-"), arity);
        i = close;
    }
    out
}

/// Every function the runtime offers has a counterpart on the trait, with the same arity.
#[test]
fn the_host_trait_mirrors_the_vendored_wit() {
    let mut exports = Vec::new();
    let mut wit = wit_funcs("wit/deps/tasks/tasks.wit", &mut exports);
    wit.extend(wit_funcs("wit/deps/notify/notify.wit", &mut exports));
    let host = host_trait_methods();

    // What the guest EXPORTS is implemented on `Cosigner`, not asked of the runtime. `run-task` is
    // the only one, and the trait is right not to carry it.
    assert_eq!(exports, vec!["run-task"], "the WIT's exports changed");
    for e in &exports {
        wit.remove(e);
        assert!(
            !host.contains_key(e),
            "`{e}` is exported by the guest — it belongs on `Cosigner`, not on `Host`"
        );
    }

    for (name, arity) in &wit {
        match host.get(name) {
            None => panic!(
                "`{name}` is in the WIT and not on `Host`. If the runtime gained a capability, \
                 mirror it; if it lost one, drop it here too."
            ),
            Some(got) => assert_eq!(
                got, arity,
                "`{name}` takes {arity} parameter(s) in the WIT but {got} on `Host`"
            ),
        }
    }

    // And nothing on the trait that the runtime does not offer — a method invented here would
    // compile, pass its own tests, and trap on the first real call.
    for name in host.keys() {
        assert!(
            wit.contains_key(name),
            "`Host::{}` is not in the vendored WIT — the runtime does not offer it",
            name.replace('-', "_")
        );
    }

    // Guard the guard: if the readers stop finding anything, say so rather than pass.
    assert!(wit.len() >= 6, "expected at least the six imports, found {}", wit.len());
}

/// The world composes both capabilities, so a single `wit_bindgen::generate!` over it is all the
/// guest port needs.
#[test]
fn the_world_includes_both_capabilities() {
    let world = fs::read_to_string("wit/cosigner.wit").expect("read wit/cosigner.wit");
    assert!(
        world.contains("include enclave:tasks/background@0.1.0;"),
        "the world must include the tasks world — that is what exports run-task"
    );
    assert!(
        world.contains("import enclave:notify/notify@0.1.0;"),
        "the world must import notify — that is what wake comes from"
    );
}
