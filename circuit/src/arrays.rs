// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

use crate::TestCircuitHandle;
use aptos_crypto::poseidon_bn254;
use aptos_keyless_common::input_processing::{
    circuit_input_signals::CircuitInputSignals, config::CircuitConfig,
};
use ark_bn254::Fr;
use ark_ff::{One, Zero};
use rand::{thread_rng, Rng};

fn build_array_selector_output(len: u32, start: u32, end: u32) -> Vec<u8> {
    let len = len as usize;
    let start = start as usize;
    let end = end as usize;

    [vec![0; start], vec![1; end - start], vec![0; len - end]].concat()
}

fn build_array_selector_complex_output(len: u32, start: u32, end: u32) -> Vec<u8> {
    if start >= end {
        return vec![0; len as usize];
    }
    build_array_selector_output(len, start, end)
}

fn build_invert_binary_array_output(input: Vec<bool>) -> Vec<bool> {
    input.into_iter().map(|x| !x).collect()
}

// Tests that the InvertBinaryArray subcircuit works for every permutation of inputs of size 4
#[test]
fn invert_binary_array_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/invert_binary_array_test.circom").unwrap();

    for b0 in [true, false] {
        for b1 in [true, false] {
            for b2 in [true, false] {
                for b3 in [true, false] {
                    let test_case = [b0, b1, b2, b3];
                    let output = build_invert_binary_array_output(test_case.to_vec());
                    let config = CircuitConfig::new()
                        .max_length("in", output.len() as usize)
                        .max_length("expected_out", output.len() as usize);
                    let circuit_input_signals = CircuitInputSignals::new()
                        .bytes_input(
                            "in",
                            &test_case.into_iter().map(|x| x as u8).collect::<Vec<u8>>()[..],
                        )
                        .bytes_input(
                            "expected_out",
                            &output.into_iter().map(|x| x as u8).collect::<Vec<u8>>()[..],
                        )
                        .pad(&config)
                        .unwrap();
                    let result = circuit_handle.gen_witness(circuit_input_signals);
                    println!("{:?}", result);
                    assert!(result.is_ok());
                }
            }
        }
    }
}

// Tests that the ElementwiseMul subcircuit works using random inputs of size 5
#[test]
fn elementwise_mul_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/elementwise_mul_test.circom").unwrap();

    let mut rng = rand::thread_rng();
    for _i in 0..25 {
        let test_case_left: Vec<u64> = (0..4)
            .map(|_| rng.gen_range(0, (u64::MAX as f64).sqrt() as u64))
            .collect();
        let test_case_right: Vec<u64> = (0..4)
            .map(|_| rng.gen_range(0, (u64::MAX as f64).sqrt() as u64))
            .collect();
        let output: Vec<u64> = test_case_left
            .clone()
            .into_iter()
            .zip(test_case_right.clone())
            .map(|(x, y)| x * y)
            .collect();
        let test_case_left_frs: Vec<Fr> = test_case_left.into_iter().map(Fr::from).collect();
        let test_case_right_frs: Vec<Fr> = test_case_right.into_iter().map(Fr::from).collect();
        let output_frs: Vec<Fr> = output.clone().into_iter().map(Fr::from).collect();

        let config = CircuitConfig::new()
            .max_length("left", output.len())
            .max_length("right", output.len())
            .max_length("expected_out", output.len());
        let circuit_input_signals = CircuitInputSignals::new()
            .frs_input("left", &test_case_left_frs)
            .frs_input("right", &test_case_right_frs)
            .frs_input("expected_out", &output_frs)
            .pad(&config)
            .unwrap();
        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn array_selector_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test.circom").unwrap();
    let out_len = 8;
    for start in 0..out_len {
        for end in start + 1..=out_len {
            let output = build_array_selector_output(out_len, start, end);
            let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
            let circuit_input_signals = CircuitInputSignals::new()
                .u64_input("start_index", start as u64)
                .u64_input("end_index", end as u64)
                .bytes_input("expected_output", &output[..])
                .pad(&config)
                .unwrap();
            let result = circuit_handle.gen_witness(circuit_input_signals);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn array_selector_test_large() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test_large.circom").unwrap();
    for _i in 0..10 {
        let mut rng = thread_rng();

        let out_len = 2000;
        let start = rng.gen_range(0, 2000);
        let end = rng.gen_range(start + 1, 2001);

        let output = build_array_selector_output(out_len, start, end);
        let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("start_index", start as u64)
            .u64_input("end_index", end as u64)
            .bytes_input("expected_output", &output)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn array_selector_test_small() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test_small.circom").unwrap();
    let out_len = 2;
    let start = 0;
    let end = 1;
    let output = build_array_selector_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn array_selector_test_wrong_start() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test.circom").unwrap();
    let out_len = 8;
    let start = 3;
    let end = 3;
    let output = build_array_selector_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn array_selector_test_reverse_start() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test.circom").unwrap();
    let out_len = 8;
    let start = 5;
    let end = 3;
    let output = build_array_selector_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn array_selector_test_out_of_bounds() {
    let circuit_handle = TestCircuitHandle::new("arrays/array_selector_test.circom").unwrap();
    let out_len = 8;
    let start = 8;
    let end = 11;
    let output = build_array_selector_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn array_selector_test_complex() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/array_selector_complex_test.circom").unwrap();
    let out_len = 8;
    // Fails when start = 0 by design
    for start in 1..out_len {
        for end in start + 1..out_len {
            let output = build_array_selector_complex_output(out_len, start, end);
            let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
            let circuit_input_signals = CircuitInputSignals::new()
                .u64_input("start_index", start as u64)
                .u64_input("end_index", end as u64)
                .bytes_input("expected_output", &output[..])
                .pad(&config)
                .unwrap();
            let result = circuit_handle.gen_witness(circuit_input_signals);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn array_selector_test_complex_large() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/array_selector_complex_large_test.circom").unwrap();
    let out_len = 2000;
    let start = 157;
    let end = 1143;
    let output = build_array_selector_complex_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn array_selector_test_complex_small() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/array_selector_complex_small_test.circom").unwrap();
    let out_len = 3;
    let start = 1;
    let end = 2;
    let output = build_array_selector_complex_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn array_selector_test_complex_wrong_start() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/array_selector_complex_test.circom").unwrap();
    let out_len = 8;
    let start = 3;
    let end = 3;
    let output = build_array_selector_complex_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn array_selector_test_complex_reverse_start() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/array_selector_complex_test.circom").unwrap();
    let out_len = 8;
    let start = 5;
    let end = 3;
    let output = build_array_selector_complex_output(out_len, start, end);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("start_index", start as u64)
        .u64_input("end_index", end as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

fn build_left_array_selector_output(len: u32, index: u32) -> Vec<u8> {
    let len = len as usize;
    let index = index as usize;
    [vec![1; index], vec![0; len - index]].concat()
}

#[test]
fn left_array_selector_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/left_array_selector_test.circom").unwrap();
    let out_len = 8;
    for index in 0..out_len {
        let output = build_left_array_selector_output(out_len, index);
        let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("index", index as u64)
            .bytes_input("expected_output", &output[..])
            .pad(&config)
            .unwrap();
        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn left_array_selector_test_large() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/left_array_selector_large_test.circom").unwrap();
    let out_len = 2000;
    let mut rng = thread_rng();
    let index = rng.gen_range(0, 2000);
    let output = build_left_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn left_array_selector_test_small() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/left_array_selector_small_test.circom").unwrap();
    let out_len = 1;
    let index = 0;
    let output = build_left_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn left_array_selector_test_out_of_bounds() {
    let circuit_handle = TestCircuitHandle::new("arrays/left_array_selector_test.circom").unwrap();
    let out_len = 8;
    let index = 9;
    let output = build_left_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

fn build_right_array_selector_output(len: usize, index: usize) -> Vec<u8> {
    if index < len {
        [vec![0; index + 1], vec![1; len - index - 1]].concat()
    } else {
        vec![0; len]
    }
}

#[test]
fn right_array_selector_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/right_array_selector_test.circom").unwrap();
    let out_len = 8;
    for index in 0..out_len {
        let output = build_right_array_selector_output(out_len, index);
        let config = CircuitConfig::new().max_length("expected_output", out_len);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("index", index as u64)
            .bytes_input("expected_output", &output[..])
            .pad(&config)
            .unwrap();
        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn right_array_selector_test_large() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/right_array_selector_large_test.circom").unwrap();
    let out_len = 2000;
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0, 2001);
    let output = build_right_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn right_array_selector_test_small() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/right_array_selector_small_test.circom").unwrap();
    let out_len = 1;
    let index = 0;
    let output = build_left_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn right_array_selector_test_out_of_bounds() {
    let circuit_handle = TestCircuitHandle::new("arrays/right_array_selector_test.circom").unwrap();
    let out_len = 8;
    let index = 9;
    let output = build_left_array_selector_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

fn build_single_one_array_output(len: usize, index: usize) -> Vec<u8> {
    let mut output = vec![0; len];

    if index < len {
        output[index] = 1;
    }
    output
}

#[test]
fn single_one_array_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/single_one_array_test.circom").unwrap();
    let out_len = 8;
    for index in 0..out_len {
        let output = build_single_one_array_output(out_len, index);
        let config = CircuitConfig::new().max_length("expected_output", out_len);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("index", index as u64)
            .bytes_input("expected_output", &output)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
#[should_panic]
fn single_one_array_out_of_bounds_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/single_one_array_test.circom").unwrap();
    let out_len = 8;
    let index = 9;
    let output = build_single_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn single_one_array_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/single_one_array_large_test.circom").unwrap();
    let out_len = 2000;
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0, 2001);
    let output = build_single_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn single_one_array_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/single_one_array_small_test.circom").unwrap();
    let out_len = 1;
    let index = 0;
    let output = build_single_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn select_array_value_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/select_array_value_test.circom").unwrap();
    let mut rng = rand::thread_rng();
    let array: Vec<u8> = (0..8).map(|_| rng.gen_range(0, 250)).collect();

    let in_len = array.len();
    for index in 0..in_len {
        let output = array[index];
        let config = CircuitConfig::new().max_length("array", in_len);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("index", index as u64)
            .bytes_input("array", &array[..])
            .u64_input("expected_output", output as u64)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
#[should_panic]
fn select_array_value_out_of_bounds_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/select_array_value_test.circom").unwrap();
    let mut rng = rand::thread_rng();
    let array: Vec<u8> = (0..8).map(|_| rng.gen_range(0, 250)).collect();

    let in_len = array.len();
    let index = 20;
    let output = array[index];
    let config = CircuitConfig::new().max_length("array", in_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("array", &array[..])
        .u64_input("expected_output", output as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn select_array_value_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/select_array_value_large_test.circom").unwrap();
    let mut rng = rand::thread_rng();
    let input: Vec<u8> = (0..2000).map(|_| rng.gen_range(0, 250)).collect();

    let index = 1567;
    let in_len = input.len();
    let output = input[index];
    let config = CircuitConfig::new().max_length("array", in_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("array", &input)
        .u64_input("expected_output", output as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn select_array_value_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/select_array_value_small_test.circom").unwrap();
    let mut rng = rand::thread_rng();
    let array: Vec<u8> = (0..1).map(|_| rng.gen_range(0, 250)).collect();
    let index = 0;
    let in_len = array.len();
    let output = array[index];
    let config = CircuitConfig::new().max_length("array", in_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("array", &array)
        .u64_input("expected_output", output as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn select_array_value_test_wrong_index() {
    let circuit_handle = TestCircuitHandle::new("arrays/select_array_value_test.circom").unwrap();
    let out_len = 8;
    let index = 8;
    let mut rng = rand::thread_rng();
    let output: Vec<u8> = (0..8).map(|_| rng.gen_range(0, 250)).collect();

    let config = CircuitConfig::new().max_length("expected_output", out_len as usize);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .bytes_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

fn build_single_neg_one_array_output(len: usize, index: usize) -> Vec<Fr> {
    if index >= len {
        return vec![Fr::zero(); len];
    }
    let mut output = vec![Fr::zero(); len];
    if index < len {
        output[index] = Fr::zero() - Fr::one();
    }
    output
}

#[test]
fn single_neg_one_array_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/single_neg_one_array_test.circom").unwrap();
    let out_len = 8;
    for index in 0..=out_len {
        let output = build_single_neg_one_array_output(out_len, index);
        let config = CircuitConfig::new().max_length("expected_output", out_len);
        let circuit_input_signals = CircuitInputSignals::new()
            .u64_input("index", index as u64)
            .frs_input("expected_output", &output)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn single_neg_one_array_out_of_bounds_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/single_neg_one_array_test.circom").unwrap();
    let out_len = 8;
    let index = 8;
    let output = build_single_neg_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .frs_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn single_neg_one_array_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/single_neg_one_array_large_test.circom").unwrap();
    let out_len = 2000;
    let mut rng = rand::thread_rng();
    let index = rng.gen_range(0, 2001);
    let output = build_single_neg_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .frs_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn single_neg_one_array_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/single_neg_one_array_small_test.circom").unwrap();
    let out_len = 1;
    let index = 0;
    let output = build_single_neg_one_array_output(out_len, index);
    let config = CircuitConfig::new().max_length("expected_output", out_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("index", index as u64)
        .frs_input("expected_output", &output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_test.circom").unwrap();

    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "Hello World!";
    let string_len = string.len();
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    for substring_len in 1..string_len {
        for start_index in 0..string_len - substring_len {
            let substring = &string[start_index..start_index + substring_len]; //"lo Wor";

            let circuit_input_signals = CircuitInputSignals::new()
                .str_input("str", string)
                .str_input("substr", substring)
                .u64_input("substr_len", substring_len as u64)
                .u64_input("start_index", start_index as u64)
                .fr_input("str_hash", string_hash)
                .pad(&config)
                .unwrap();

            let result = circuit_handle.gen_witness(circuit_input_signals);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn check_substr_inclusion_poly_no_padding_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_no_padding_test.circom")
            .unwrap();

    let string = "Hello World!";
    let max_str_len = string.len();
    let max_substr_len = 11;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_len = string.len();
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring_len = 3;
    for start_index in 0..string_len - substring_len {
        let substring = &string[start_index..start_index + substring_len]; //"lo Wor";

        let circuit_input_signals = CircuitInputSignals::new()
            .str_input("str", string)
            .str_input("substr", substring)
            .u64_input("substr_len", substring_len as u64)
            .u64_input("start_index", start_index as u64)
            .fr_input("str_hash", string_hash)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn check_substr_inclusion_poly_same_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_test.circom").unwrap();

    let string = "Hello World!";
    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring = string;
    let substring_len = substring.len();
    let start_index = 0;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index as u64)
        .fr_input("str_hash", string_hash)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_out_of_bounds_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_test.circom").unwrap();

    let string = "Hello World!";
    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring = "____bad____";
    let substring_len = substring.len();
    let start_index = 1000;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index as u64)
        .fr_input("str_hash", string_hash)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_err());
}

#[test]
fn check_substr_inclusion_poly_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_large_test.circom").unwrap();

    let max_str_len = 2000;
    let max_substr_len = 1000;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "Once upon a midnight dreary, while I pondered, weak and weary,
Over many a quaint and curious volume of forgotten lore—
    While I nodded, nearly napping, suddenly there came a tapping,
As of some one gently rapping, rapping at my chamber door.
“’Tis some visitor,” I muttered, “tapping at my chamber door—";
    let string_hash = poseidon_bn254::pad_and_hash_string("dummy string", 30).unwrap(); // Hash is not checked in the substring inclusion protocol and so can be arbitrary here
    let substring = &string[45..70];
    let substring_len = substring.len();
    let start_index = 45;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index)
        .fr_input("str_hash", string_hash)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_test.circom").unwrap();

    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "a";
    let string_hash = poseidon_bn254::pad_and_hash_string("dummy string", 30).unwrap(); // Hash is not checked in the substring inclusion protocol and so can be arbitrary here
    let substring = "a";
    let substring_len = substring.len();
    let start_index = 0;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index)
        .fr_input("str_hash", string_hash)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_edge_case_test() {
    let circuit_handle = TestCircuitHandle::new("check_substr_inclusion_poly_test.circom").unwrap();

    let test_str: &'static [u8] = &[
        4u8, 233, 24, 159, 105, 83, 145, 69, 245, 99, 150, 28, 197, 219, 186, 204, 47, 219, 5, 139,
        89, 15, 216, 169, 206, 145, 224, 32, 59, 0, 178, 44, 116, 149, 61, 64, 149, 134, 204, 103,
        18, 57, 87, 168, 144, 26, 173, 48, 219, 125, 64, 211, 131, 159, 76, 29, 154, 118, 163, 18,
        38, 24, 44, 191, 196, 36, 240, 250, 82, 176, 94, 86, 202, 67, 142, 19, 115, 237, 104, 190,
        28, 122, 44, 252, 139, 106, 125, 145, 135, 1, 181, 127, 0, 242, 187, 80, 208, 51, 22, 1,
        194, 159, 218, 16, 33, 113, 220, 214, 209, 168, 195, 83, 177, 149, 74, 20, 7, 28, 124, 175,
        212, 240, 55, 96, 155, 163, 158, 94, 64, 141, 154, 111, 89, 219, 90, 16, 142, 139, 215,
        124, 141, 19, 94, 73, 24, 213, 204, 15, 221, 86, 52, 132, 246, 58, 133, 94, 193, 36, 12,
        232, 37, 209, 171, 118, 85, 13, 154, 180, 124, 188, 81, 235, 254, 114, 114, 101, 75, 161,
        208, 227, 71, 22, 48, 204, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 192,
    ];
    let str_hash = poseidon_bn254::pad_and_hash_bytes_with_len(test_str, 256).unwrap();
    let substr: &'static [u8] = &[0u8, 0, 0, 0, 0, 0, 5, 192];
    let start_index = 248;

    let config = CircuitConfig::new()
        .max_length("str", 256)
        .max_length("substr", 8);

    let circuit_input_signals = CircuitInputSignals::new()
        .bytes_input("str", test_str)
        .fr_input("str_hash", str_hash)
        .bytes_input("substr", substr)
        .usize_input("substr_len", substr.len())
        .usize_input("start_index", start_index)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);

    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_boolean_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_test.circom").unwrap();

    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "Hello World!";
    let string_len = string.len();
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    for substring_len in 1..string_len {
        for start_index in 0..string_len - substring_len {
            let substring = &string[start_index..start_index + substring_len];

            let circuit_input_signals = CircuitInputSignals::new()
                .str_input("str", string)
                .str_input("substr", substring)
                .u64_input("substr_len", substring_len as u64)
                .u64_input("start_index", start_index as u64)
                .fr_input("str_hash", string_hash)
                .u64_input("expected_output", 1)
                .pad(&config)
                .unwrap();

            let result = circuit_handle.gen_witness(circuit_input_signals);
            assert!(result.is_ok());
        }
    }
}

#[test]
fn check_substr_inclusion_poly_no_padding_boolean_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_no_padding_test.circom")
            .unwrap();

    let string = "Hello World!";
    let max_str_len = string.len();
    let max_substr_len = 11;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_len = string.len();
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring_len = 3;
    for start_index in 0..string_len - substring_len {
        let substring = &string[start_index..start_index + substring_len]; //"lo Wor";

        let circuit_input_signals = CircuitInputSignals::new()
            .str_input("str", string)
            .str_input("substr", substring)
            .u64_input("substr_len", substring_len as u64)
            .u64_input("start_index", start_index as u64)
            .fr_input("str_hash", string_hash)
            .u64_input("expected_output", 1)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
fn check_substr_inclusion_poly_same_boolean_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_test.circom").unwrap();

    let string = "Hello World!";
    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring = string;
    let substring_len = substring.len();
    let start_index = 0;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index as u64)
        .fr_input("str_hash", string_hash)
        .u64_input("expected_output", 1)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_boolean_out_of_bounds_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_test.circom").unwrap();

    let string = "Hello World!";
    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string_hash = poseidon_bn254::pad_and_hash_string(string, max_str_len).unwrap();
    let substring = "____bad____";
    let substring_len = substring.len();
    let start_index = 1000;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index as u64)
        .fr_input("str_hash", string_hash)
        .u64_input("expected_output", 1)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_err());
}

#[test]
fn check_substr_inclusion_poly_large_boolean_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_large_test.circom")
            .unwrap();

    let max_str_len = 2000;
    let max_substr_len = 1000;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "Once upon a midnight dreary, while I pondered, weak and weary,
Over many a quaint and curious volume of forgotten lore—
    While I nodded, nearly napping, suddenly there came a tapping,
As of some one gently rapping, rapping at my chamber door.
“’Tis some visitor,” I muttered, “tapping at my chamber door—";
    let string_hash = poseidon_bn254::pad_and_hash_string("dummy string", 30).unwrap(); // Hash is not checked in the substring inclusion protocol and so can be arbitrary here
    let substring = &string[45..70];
    let substring_len = substring.len();
    let start_index = 45;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index)
        .fr_input("str_hash", string_hash)
        .u64_input("expected_output", 1)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_substr_inclusion_poly_small_boolean_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_substr_inclusion_poly_boolean_test.circom").unwrap();

    let max_str_len = 100;
    let max_substr_len = 20;
    let config = CircuitConfig::new()
        .max_length("str", max_str_len)
        .max_length("substr", max_substr_len);
    let string = "a";
    let string_hash = poseidon_bn254::pad_and_hash_string("dummy string", 30).unwrap(); // Hash is not checked in the substring inclusion protocol and so can be arbitrary here
    let substring = "a";
    let substring_len = substring.len();
    let start_index = 0;

    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("str", string)
        .str_input("substr", substring)
        .u64_input("substr_len", substring_len as u64)
        .u64_input("start_index", start_index)
        .fr_input("str_hash", string_hash)
        .u64_input("expected_output", 1)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn concatenation_check_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/concatenation_check_test.circom").unwrap();

    let max_full_str_len = 100;
    let max_left_str_len = 70;
    let max_right_str_len = 70;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "Hello World!";
    let str_len = full_string.len();
    // Subcircuit fails if the left string is empty
    for sep_index in 1..str_len {
        let left_string = &full_string[0..sep_index];
        let right_string = &full_string[sep_index..full_string.len()];
        let left_len = left_string.len();
        let right_len = right_string.len();
        let circuit_input_signals = CircuitInputSignals::new()
            .str_input("full_string", full_string)
            .str_input("left", left_string)
            .str_input("right", right_string)
            .u64_input("left_len", left_len as u64)
            .u64_input("right_len", right_len as u64)
            .pad(&config)
            .unwrap();

        let result = circuit_handle.gen_witness(circuit_input_signals);
        assert!(result.is_ok());
    }
}

#[test]
#[should_panic]
fn concatenation_check_left_len_wrong_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/concatenation_check_test.circom").unwrap();

    let max_full_str_len = 100;
    let max_left_str_len = 70;
    let max_right_str_len = 70;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "Hello World!";
    let str_len = full_string.len();
    let sep_index = 3;
    let left_string = &full_string[0..sep_index];
    let right_string = &full_string[sep_index..str_len];
    let left_len = 72;
    let right_len = right_string.len();
    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("full_string", full_string)
        .str_input("left", left_string)
        .str_input("right", right_string)
        .u64_input("left_len", left_len as u64)
        .u64_input("right_len", right_len as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn concatenation_check_left_string_wrong_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/concatenation_check_test.circom").unwrap();

    let max_full_str_len = 100;
    let max_left_str_len = 70;
    let max_right_str_len = 70;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "Hello World!";
    let str_len = full_string.len();
    let sep_index = 3;
    let left_string = &full_string[0..sep_index - 1];
    let right_string = &full_string[sep_index..str_len];
    let left_len = left_string.len();
    let right_len = right_string.len();
    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("full_string", full_string)
        .str_input("left", left_string)
        .str_input("right", right_string)
        .u64_input("left_len", left_len as u64)
        .u64_input("right_len", right_len as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn concatenation_check_right_string_wrong_test() {
    let circuit_handle = TestCircuitHandle::new("arrays/concatenation_check_test.circom").unwrap();

    let max_full_str_len = 100;
    let max_left_str_len = 70;
    let max_right_str_len = 70;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "Hello World!";
    let str_len = full_string.len();
    // Subcircuit fails if the left string is empty
    let sep_index = 3;
    let left_string = &full_string[0..sep_index];
    let right_string = &full_string[sep_index..str_len - 1];
    let left_len = left_string.len();
    let right_len = right_string.len();
    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("full_string", full_string)
        .str_input("left", left_string)
        .str_input("right", right_string)
        .u64_input("left_len", left_len as u64)
        .u64_input("right_len", right_len as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn concatenation_check_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/concatenation_check_small_test.circom").unwrap();

    let max_full_str_len = 2;
    let max_left_str_len = 1;
    let max_right_str_len = 1;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "ab";
    let str_len = full_string.len();
    let sep_index = 1;
    let left_string = &full_string[0..sep_index];
    let right_string = &full_string[sep_index..str_len];
    let left_len = left_string.len();
    let right_len = right_string.len();
    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("full_string", full_string)
        .str_input("left", left_string)
        .str_input("right", right_string)
        .u64_input("left_len", left_len as u64)
        .u64_input("right_len", right_len as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn concatenation_check_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/concatenation_check_large_test.circom").unwrap();

    let max_full_str_len = 1600;
    let max_left_str_len = 1000;
    let max_right_str_len = 1000;
    let config = CircuitConfig::new()
        .max_length("full_string", max_full_str_len)
        .max_length("left", max_left_str_len)
        .max_length("right", max_right_str_len);
    let full_string = "Once upon a midnight dreary, while I pondered, weak and weary,
    Over many a quaint and curious volume of forgotten lore—
    While I nodded, nearly napping, suddenly there came a tapping,
    As of some one gently rapping, rapping at my chamber door.
    “’Tis some visitor,” I muttered, “tapping at my chamber door—";
    let str_len = full_string.len();
    let sep_index = 31;
    let left_string = &full_string[0..sep_index];
    let right_string = &full_string[sep_index..str_len];
    let left_len = left_string.len();
    let right_len = right_string.len();
    let circuit_input_signals = CircuitInputSignals::new()
        .str_input("full_string", full_string)
        .str_input("left", left_string)
        .str_input("right", right_string)
        .u64_input("left_len", left_len as u64)
        .u64_input("right_len", right_len as u64)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_are_ascii_digits_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_are_ascii_digits_test.circom").unwrap();
    let max_input_len = 20;

    let mut rng = rand::thread_rng();
    let digits: Vec<u8> = (0..5).map(|_| rng.gen_range(0, 9)).collect();
    let mut input_arr = digits_to_ascii_digits(digits.to_vec());
    let mut not_digits: Vec<u8> = (0..8 - 5).map(|_| rng.gen_range(58, 250)).collect();
    input_arr.append(&mut not_digits);

    let len = 5; // only the first 5 entries should need to be valid digits
    let config = CircuitConfig::new().max_length("in", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("in", &input_arr)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_are_ascii_digits_out_of_bounds_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_are_ascii_digits_test.circom").unwrap();
    let max_input_len = 20;

    let mut rng = rand::thread_rng();
    let len = 22;
    let digits: Vec<u8> = (0..20).map(|_| rng.gen_range(0, 9)).collect();
    let input_arr = digits_to_ascii_digits(digits.to_vec());

    let config = CircuitConfig::new().max_length("in", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("in", &input_arr)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_are_ascii_digits_max_len_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_are_ascii_digits_max_len_test.circom").unwrap();
    let max_input_len = 8;
    let mut rng = rand::thread_rng();
    let digits: Vec<u8> = (0..8).map(|_| rng.gen_range(0, 9)).collect();
    let input_arr = digits_to_ascii_digits(digits.to_vec());
    let len = input_arr.len();
    let config = CircuitConfig::new().max_length("in", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len as u64)
        .bytes_input("in", &input_arr)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_are_ascii_digits_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_are_ascii_digits_test.circom").unwrap();
    let max_input_len = 20;
    let mut rng = rand::thread_rng();
    let digits: Vec<u8> = (0..1).map(|_| rng.gen_range(0, 9)).collect();
    let input_arr = digits_to_ascii_digits(digits.to_vec());
    let len = 1;
    let config = CircuitConfig::new().max_length("in", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("in", &input_arr)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn check_are_ascii_digits_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/check_are_ascii_digits_large_test.circom").unwrap();
    let max_input_len = 2000;
    let mut rng = rand::thread_rng();
    let digits: Vec<u8> = (0..1523).map(|_| rng.gen_range(0, 9)).collect();
    let input_arr = digits_to_ascii_digits(digits.to_vec());

    let len = input_arr.len();
    let config = CircuitConfig::new().max_length("in", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len as u64)
        .bytes_input("in", &input_arr)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

fn digits_to_ascii_digits(digits: Vec<u8>) -> Vec<u8> {
    let mut result = digits.clone();
    for digit in &mut result {
        *digit += 48;
    }
    result
}

#[test]
fn ascii_digits_to_field_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/ascii_digits_to_field_test.circom").unwrap();
    let max_input_len = 20;
    let digits = [2, 1, 2, 4, 7];

    let ascii_digits = digits_to_ascii_digits(digits.to_vec());
    let len = 5;
    let expected_output = 21247;
    let config = CircuitConfig::new().max_length("digits", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("digits", &ascii_digits)
        .u64_input("expected_output", expected_output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn ascii_digits_to_field_out_of_bounds_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/ascii_digits_to_field_test.circom").unwrap();
    let max_input_len = 20;
    let digits = [2, 1, 2, 4, 7];

    let ascii_digits = digits_to_ascii_digits(digits.to_vec());
    let len = 22;
    let expected_output = 21247;
    let config = CircuitConfig::new().max_length("digits", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("digits", &ascii_digits)
        .u64_input("expected_output", expected_output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_err());
}

#[test]
fn ascii_digits_to_field_small_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/ascii_digits_to_field_small_test.circom").unwrap();
    let max_input_len = 2;
    let digits = [7, 89];
    let ascii_digits = digits_to_ascii_digits(digits.to_vec());
    let len = 1;
    let expected_output = 7;
    let config = CircuitConfig::new().max_length("digits", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("digits", &ascii_digits)
        .u64_input("expected_output", expected_output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
fn ascii_digits_to_field_large_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/ascii_digits_to_field_large_test.circom").unwrap();
    let max_input_len = 2000;
    // let mut rng = rand::thread_rng();
    // let digits: Vec<u8> = (0..19).map(|_| rng.gen_range(0, 9)).collect();

    let digits = [
        2, 1, 2, 4, 7, 4, 8, 0, 1, 9, 2, 1, 8, 3, 6, 7, 4, 1, 5, 14, 41, 180, 1, 31, 47, 2, 3, 6,
        7, 31, 35,
    ];
    let ascii_digits = digits_to_ascii_digits(digits.to_vec());

    let len = 19;
    let expected_output = 2124748019218367415;
    let config = CircuitConfig::new().max_length("digits", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("digits", &ascii_digits)
        .u64_input("expected_output", expected_output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}

#[test]
#[should_panic]
fn ascii_digits_to_field_not_ascii_digits_test() {
    let circuit_handle =
        TestCircuitHandle::new("arrays/ascii_digits_to_field_test.circom").unwrap();
    let max_input_len = 20;
    let digits = [2, 1, 24, 4, 7];
    let ascii_digits = digits_to_ascii_digits(digits.to_vec());
    let len = 5;
    let expected_output = 21247;
    let config = CircuitConfig::new().max_length("digits", max_input_len);
    let circuit_input_signals = CircuitInputSignals::new()
        .u64_input("len", len)
        .bytes_input("digits", &ascii_digits)
        .u64_input("expected_output", expected_output)
        .pad(&config)
        .unwrap();

    let result = circuit_handle.gen_witness(circuit_input_signals);
    assert!(result.is_ok());
}
