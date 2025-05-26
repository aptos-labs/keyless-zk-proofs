pragma circom 2.2.2;

include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/gates.circom";

// Checks if character 'char' is a whitespace character. Returns 1 if so, 0 otherwise
// Assumes char is a valid ascii character. Does not check for non-ascii unicode whitespace chars.
template IsWhitespace() {
   signal input char;  
                       
   // ASCII bytes in [9, 13] are line break characters:
   //   tab -- 9, newline -- 10, vertical tab -- 11,
   //   form feed -- 12, carriage return -- 13
   signal is_line_break_part_1 <== GreaterThan(8)([char, 8]);
   signal is_line_break_part_2 <== LessThan(8)([char, 14]);
   signal is_line_break <== AND()(is_line_break_part_1, is_line_break_part_2);

   // 32 in ASCII is the space character
   signal is_space <== IsEqual()([char, 32]);

   // serves as a cheaper logical OR, when we know:
   //   (1) values are either 0 or 1 and
   //   (2) both values CANNOT be 1 at the same time
   signal output is_whitespace <== is_line_break + is_space;
}