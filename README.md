# sha3-hash

This library provides an easy-to-use SHA-3 hash type. It can be serialized and
deserialized via [Serde](serde), and supports all expected operations.

Here is an example of how you might use this library to compute a SHA-3 hash:

```rust
let data = "Hello World!";
let hash = sha3_hash::Hash::hash_bytes(data.as_bytes());

// Prints: d0e47486bbf4c16acac26f8b653592973c1362909f90262877089f9c8a4536af
println!("{}", hash);

// Serializing the hash to a JSON string using `serde_json`
let json_string = serde_json::to_string(&hash).unwrap();
```

Adding `sha3-hash` to `Cargo.toml`:

```toml
[dependencies]
sha3-hash = "0.1"
```
