module permutation(
    input [  3:0] rc,
    input [319:0] in_s,
    output[319:0] out_s
    );

    wire[319:0] state_c;
    wire[319:0] state_s;
    wire[319:0] state_l;

    //Addition of constants
    assign state_c[319-:192] = in_s[319-:192] ^ {~rc, rc};
    assign state_c[127-:128] = in_s[127-:128];

    //Substitution layer
    function [4:0] sbox;
    input [4:0] x;
    begin
        case (x)
            5'h00: sbox = 5'h04;
            5'h01: sbox = 5'h0B;
            5'h02: sbox = 5'h1F;
            5'h03: sbox = 5'h14;
            5'h04: sbox = 5'h1A;
            5'h05: sbox = 5'h15;
            5'h06: sbox = 5'h09;
            5'h07: sbox = 5'h02;
            5'h08: sbox = 5'h1B;
            5'h09: sbox = 5'h05;
            5'h0A: sbox = 5'h08;
            5'h0B: sbox = 5'h12;
            5'h0C: sbox = 5'h1D;
            5'h0D: sbox = 5'h03;
            5'h0E: sbox = 5'h06;
            5'h0F: sbox = 5'h1C;
            5'h10: sbox = 5'h1E;
            5'h11: sbox = 5'h13;
            5'h12: sbox = 5'h07;
            5'h13: sbox = 5'h0E;
            5'h14: sbox = 5'h00;
            5'h15: sbox = 5'h0D;
            5'h16: sbox = 5'h11;
            5'h17: sbox = 5'h18;
            5'h18: sbox = 5'h10;
            5'h19: sbox = 5'h0C;
            5'h1A: sbox = 5'h01;
            5'h1B: sbox = 5'h19;
            5'h1C: sbox = 5'h16;
            5'h1D: sbox = 5'h0A;
            5'h1E: sbox = 5'h0F;
            5'h1F: sbox = 5'h17;
            default: sbox = 5'h00; // Default case for safety
        endcase
    end
    endfunction
    genvar i;
    generate
        for (i = 0; i < 64; i = i + 1) begin
            assign {state_s[319-i], state_s[255-i], state_s[191-i], state_s[127-i], state_s[63-i]}
            = sbox({state_c[319-i], state_c[255-i], state_c[191-i], state_c[127-i], state_c[63-i]});
        end
    endgenerate

    //Linear diffusion layer
    assign state_l[319-:64] = state_s[319-:64] ^ {state_s[319-64+19-:19], state_s[319-:64-19]} ^ {state_s[319-64+28-:28], state_s[319-:64-28]};
    assign state_l[255-:64] = state_s[255-:64] ^ {state_s[255-64+61-:61], state_s[255-:64-61]} ^ {state_s[255-64+39-:39], state_s[255-:64-39]};
    assign state_l[191-:64] = state_s[191-:64] ^ {state_s[191-64+ 1-: 1], state_s[191-:64- 1]} ^ {state_s[191-64+ 6-: 6], state_s[191-:64- 6]};
    assign state_l[127-:64] = state_s[127-:64] ^ {state_s[127-64+10-:10], state_s[127-:64-10]} ^ {state_s[127-64+17-:17], state_s[127-:64-17]};
    assign state_l[ 63-:64] = state_s[ 63-:64] ^ {state_s[ 63-64+ 7-: 7], state_s[ 63-:64- 7]} ^ {state_s[ 63-64+41-:41], state_s[ 63-:64-41]};

    assign out_s   = state_l;

endmodule