//! Pattern-detection layer benchmarks.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rust_prompt_armor::Armor;

fn bench_pattern_pass(c: &mut Criterion) {
    let clean: String = "harmless plain text. ".chars().cycle().take(10_240).collect();
    c.bench_function("patterns_clean_10KB", |b| {
        b.iter(|| {
            let _ = Armor::builder().system("x").user(black_box(&clean[..])).build();
        })
    });
}

criterion_group!(benches, bench_pattern_pass);
criterion_main!(benches);
