use crate::{DPF, Group, PRG, BGI18, Z256, usize_to_bits};
use num_traits::Zero;
use rand::{Rng, thread_rng};

// Group type
type G = Z256;

fn test_eval_helper<D: DPF<G>>() {
    let mut rng = thread_rng();

    for log_domain in 2usize..12 {
        // Generate a random point in the given domain and field value
        let valid_range = 0..(1 << log_domain);
        let x = rng.gen_range(valid_range.clone());
        let y = G::sample(&mut rng);

        // Create the DPF
        let mut prg = PRG::new();
        let (key1, key2) = D::gen(log_domain, x, y, &mut prg);

        // Evaluate each point of the DPF
        for p in valid_range {
            let p_repr = usize_to_bits(log_domain, p);
            let p1_result = D::eval(&key1, &p_repr, &mut prg);
            let p2_result = D::eval(&key2, &p_repr, &mut prg);
            if p == x {
                assert!(p1_result + p2_result == y)
            } else {
                assert!(p1_result + p2_result == G::zero())
            }
        }
    }
}

fn test_full_eval_helper<D: DPF<G>>() {
    let mut rng = thread_rng();

    for log_domain in 2usize..12 { // TODO
        // Generate a random point in the given domain and field value
        let valid_range = 0..(1 << log_domain);
        let x = rng.gen_range(valid_range.clone());
        let y = G::sample(&mut rng);

        // Create the DPF
        let mut prg = PRG::new();
        let (key1, key2) = D::gen(log_domain, x, y, &mut prg);

        // Evaluate the DPF
        let p1_result = D::eval_full(&key1, &mut prg);
        let p2_result = D::eval_full(&key2, &mut prg);

        // Assert that the full evaluation matches evaluations at each individual point
        for point in 0..(1<<log_domain) {
            assert_eq!(
                p1_result[point],
                D::eval(&key1, &usize_to_bits(log_domain, point), &mut prg)
            );
            assert_eq!(
                p2_result[point],
                D::eval(&key2, &usize_to_bits(log_domain, point), &mut prg)
            );
        }
    }
}

#[test]
fn dpf_eval() {
    super::tests::test_eval_helper::<BGI18<G>>();
}

#[test]
fn dpf_full_eval() {
    super::tests::test_full_eval_helper::<BGI18<G>>();
}
