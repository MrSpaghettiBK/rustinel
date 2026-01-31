// Simple YARA demo binary. Contains a marker string used by rules/yara/example_test_string.yar.
const MARKER: &str = "RUSTINEL_TEST_MARKER";

fn main() {
    println!("{}", MARKER);
}
