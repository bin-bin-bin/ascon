`define BLOCK_ENKEY 'b000
`define BLOCK_NONCE 'b001
`define BLOCK_ASSOC 'b010
`define BLOCK_PAYLD 'b011
`define BLOCK_FINAL 'b100

module block_processor (
    input         clk,
    input         rstn,
    input         is_decrypt,
    input [  7:0] blk_len,
    input [127:0] in_blk,
    input         in_rdy,
    output        out_rdy,
    output[  2:0] blk_type,
    output[127:0] out_blk
);

    reg         out_ready;
    reg [127:0] out_block;

    reg [319:0] state;
    reg [127:0] key;

    reg [  2:0] block_flag;
    reg         assoc_mark;
    wire        has_assoc = block_flag == `BLOCK_ASSOC && (assoc_mark || blk_len > 0);

    begin : permutation
        reg [  3:0] round_cnt;
        wire[319:0] out_state;

        reg         out_pend;

        permutation p(
            .rc             (round_cnt),
            .in_s           (state),
            .out_s          (out_state)
        );

        task reset;
        begin
            round_cnt <= 12;
            out_pend  <= 0;
        end
        endtask

        task start (
            input [3:0] round_num
        );
        begin
            round_cnt <= round_num;
            out_pend  <= 1;
        end
        endtask

        task loop;
        begin
            round_cnt <= round_cnt + 1;
            state     <= out_state;
        end
        endtask
    end

    begin : pad
        wire[127:0] mask  = ~(~'b0 >> blk_len);
        wire[127:0] mask2 = ~(block_flag == `BLOCK_ASSOC || !is_decrypt ? 'b0 : mask);
        wire[127:0] delim = ~(~'b0 >> blk_len + 1) ^ mask;
        wire[127:0] block = in_blk & mask;
    end

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            permutation.reset;
            assoc_mark           <= 0;
            state                <= 'h0;
            key                  <= 'h0;
            out_block            <= 'h0;
            block_flag           <= `BLOCK_ENKEY;
            out_ready            <= 1;
        end
        else if (permutation.round_cnt < 12) permutation.loop;
        else if (in_rdy || !out_ready) begin
            out_ready            <= permutation.out_pend;
            permutation.out_pend <= 0;
            case (permutation.out_pend)
            0: case (block_flag)
               `BLOCK_ENKEY: begin
                   key                 <= in_blk;
                   block_flag          <= `BLOCK_NONCE;
                   out_ready           <= 1;
               end
               `BLOCK_NONCE: begin
                   //state initialization
                   state[319-: 32]     <= 'h80800c08; //iv filling: ascon 128a: k=128,r=128,a=12,b=8
                   state[287-: 32]     <= 'h0;
                   state[255-:128]     <= key;        //xor key
                   state[127-:128]     <= in_blk;     //xor nonce
                   assoc_mark          <= 0;
                   permutation.start(0); //initial round transformation
               end
              `BLOCK_ASSOC, `BLOCK_PAYLD: begin
                   if (blk_len > 0)
                       assoc_mark      <= 1;
                   if (has_assoc || block_flag == `BLOCK_PAYLD) begin
                       out_block       <= pad.block ^ state[319-:128] & pad.mask;
                       state[319-:128] <= pad.block ^ state[319-:128] & pad.mask2 ^ pad.delim;
                   end
                   permutation.start(has_assoc || blk_len == 128 ? 4 : 12); //intermediate permutation to the state
               end
               `BLOCK_FINAL: begin
                   state[191-:128]     <= state[191-:128] ^ key; //xor with 0_r||K||0_c-k
                   permutation.start(0); //finalizing round transformation
               end
               endcase
            1: case (block_flag)
               `BLOCK_NONCE: begin
                   state               <= state ^ key; //xor with 0*||K
                   block_flag          <= `BLOCK_ASSOC;
               end
               `BLOCK_ASSOC: begin
                   state               <= state ^ (blk_len < 128 ? 'b1 : 'b0); //xor domain separation
                   block_flag          <= blk_len < 128 ? `BLOCK_PAYLD : `BLOCK_ASSOC;
               end
               `BLOCK_PAYLD: begin
                   block_flag          <= blk_len < 128 ? `BLOCK_FINAL : `BLOCK_PAYLD;
               end
               `BLOCK_FINAL: begin
                   out_block           <= state[127-:128] ^ key; //output tag
                   block_flag          <= `BLOCK_NONCE;
               end
               endcase
            endcase
        end
    end

    assign blk_type = block_flag;
    assign out_rdy  = out_ready;
    assign out_blk  = out_block;

endmodule