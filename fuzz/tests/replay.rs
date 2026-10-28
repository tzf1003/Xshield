//! Runs every fuzz target on the stable toolchain: each checked-in seed, then
//! a fixed number of deterministic mutations of the seeds. This is not a
//! substitute for coverage-guided fuzzing; it keeps the targets compiling,
//! replays every crash ever found (they are added as seeds), and catches a
//! contract break that small mutations of valid inputs already reach.

use std::{fs, path::Path};

/// Deterministic xorshift, so a failure reproduces from the round number.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next() % u64::try_from(bound.max(1)).unwrap()).unwrap()
    }
}

/// Bytes that change how the parsers branch: separators, quotes, escapes,
/// percent-encoding, digits, high bytes and NUL.
const INTERESTING: &[u8] = b"\0\n\r /:?#&=%{}[]\",\\.-_09aAzZ@*\x7f\x80\xff";

fn mutate(random: &mut XorShift, input: &mut Vec<u8>) {
    for _ in 0..=random.below(4) {
        let at = random.below(input.len() + 1);
        match random.below(5) {
            0 if at < input.len() => input[at] = INTERESTING[random.below(INTERESTING.len())],
            1 => input.insert(at, INTERESTING[random.below(INTERESTING.len())]),
            2 if at < input.len() => {
                input.remove(at);
            }
            3 => input.truncate(at),
            _ if at < input.len() => {
                let end = (at + 1 + random.below(8)).min(input.len());
                let copy = input[at..end].to_vec();
                input.splice(at..at, copy);
            }
            _ => input.push(u8::try_from(random.below(256)).unwrap()),
        }
    }
}

fn seeds(target: &str) -> Vec<Vec<u8>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("seeds")
        .join(target);
    let mut entries: Vec<_> = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| entry.unwrap().path())
        .collect();
    entries.sort();
    let seeds: Vec<_> = entries.iter().map(|path| fs::read(path).unwrap()).collect();
    assert!(!seeds.is_empty(), "{target} has no seeds");
    seeds
}

#[test]
fn every_target_has_a_libfuzzer_entry_and_seeds() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for (name, _) in xshield_fuzz::TARGETS {
        assert!(
            root.join("fuzz_targets")
                .join(format!("{name}.rs"))
                .is_file(),
            "{name}"
        );
        assert!(!seeds(name).is_empty());
    }
    let declared = fs::read_dir(root.join("fuzz_targets")).unwrap().count();
    assert_eq!(declared, xshield_fuzz::TARGETS.len());
}

#[test]
fn seeds_and_their_mutations_keep_every_contract() {
    for (index, (name, target)) in xshield_fuzz::TARGETS.iter().enumerate() {
        let seeds = seeds(name);
        for seed in &seeds {
            target(seed);
        }
        let mut random = XorShift(0x5eed_f00d_0000_0001 ^ u64::try_from(index).unwrap());
        for _ in 0..4_000 {
            let mut input = seeds[random.below(seeds.len())].clone();
            mutate(&mut random, &mut input);
            target(&input);
        }
    }
}
