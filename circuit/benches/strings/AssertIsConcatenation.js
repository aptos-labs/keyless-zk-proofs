const chai = require("chai");
const path = require("path");
const F1Field = require("ffjavascript").F1Field;
const Scalar = require("ffjavascript").Scalar;
// BN254's prime p, but it doesn't affect circom_tester's config; need to manually pass in the prime
// exports.p = Scalar.fromString("21888242871839275222246405745257275088548364400416034343698204186575808495617");
//const Fr = new F1Field(exports.p);

const wasm_tester = require("circom_tester").wasm;

const assert = chai.assert;
const expect = chai.expect;

describe("AssertIsConcatenation", function ()  {
    this.timeout(100000);

    let CIRCOMLIB_PATH = process.env.CIRCOMLIB_PATH;
    let INCLUDE_PATH = path.join(__dirname, "../../templates/");
    // console.log("circomlib is at:", CIRCOMLIB_PATH);

    it("AssertIsConcatenation for JWTs constraints", async() => {

        const circuit = await wasm_tester(
            path.join(__dirname, "AssertIsConcatenation_Bench.circom"),
            {
                "prime": "bn128",
                "O": 2, //according to Oleksandr from iden3/circom, default was --O2 actually
                "include": [ INCLUDE_PATH, CIRCOMLIB_PATH ],
            },
        );
        
        await circuit.loadConstraints();
        console.log("AssertIsConcatenation for JWTs: %d constraints, %d vars", circuit.constraints.length, circuit.nVars);
        console.log();
    });
});
