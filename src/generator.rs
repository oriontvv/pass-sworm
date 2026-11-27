//! Password generation.
//!
//! Uniform selection over the enabled character classes, with at least one
//! character from each class as long as the requested length allows it. Character
//! classes can drop visually ambiguous glyphs (`Il1O0o`) when asked to.

use rand::distr::{Distribution, Uniform};
use rand::seq::SliceRandom;

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?";
/// Glyphs that are easy to confuse when read from a screen or printout.
const AMBIGUOUS: &str = "Il1O0o";

pub fn generate(length: usize, symbols: bool, avoid_ambiguous: bool) -> String {
    let length = length.max(1);

    let mut classes: Vec<Vec<char>> = [LOWER, UPPER, DIGITS]
        .iter()
        .map(|set| charset(set, avoid_ambiguous))
        .collect();
    if symbols {
        classes.push(charset(SYMBOLS, avoid_ambiguous));
    }
    classes.retain(|class| !class.is_empty());

    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    if pool.is_empty() {
        return String::new();
    }

    let mut rng = rand::rng();
    let mut out: Vec<char> = Vec::with_capacity(length);

    // One character per class first, so enabling symbols actually yields one.
    for class in classes.iter().take(length) {
        let dist = Uniform::new(0, class.len()).unwrap();
        out.push(class[dist.sample(&mut rng)]);
    }
    let uniform = Uniform::new(0, pool.len()).unwrap();
    while out.len() < length {
        out.push(pool[uniform.sample(&mut rng)]);
    }

    out.shuffle(&mut rng);
    out.into_iter().collect()
}

fn charset(set: &str, avoid_ambiguous: bool) -> Vec<char> {
    set.chars()
        .filter(|c| !(avoid_ambiguous && AMBIGUOUS.contains(*c)))
        .collect()
}

#[cfg(test)]
#[path = "tests/generator.rs"]
mod tests;
