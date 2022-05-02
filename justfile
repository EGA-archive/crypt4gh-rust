
test:
    cargo test --release -- --test-threads 1

check: test
    cargo +nightly fmt
    cargo +nightly udeps
    cargo outdated --depth 1