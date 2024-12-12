`timescale 1ns/100ps

module tb_block_processor(

    );

    reg clk, rstn;

    always begin : clock
        clk = 0; #0.5;
        clk = 1; #0.5;
    end
    
    task reset;
    begin
        rstn = 0;
        wait(block_proc.block_type == 0);
        rstn = 1;
    end
    endtask

    begin : block_proc
        reg in_ready;
        reg is_decrypt;
        reg[7:0] block_len;
        reg[127:0] in_block;
        wire[127:0] out_block;
        wire[2:0] block_type;
        wire out_ready;

        block_processor block_proc (
            .clk        (clk),
            .rstn       (rstn),
            .is_decrypt (is_decrypt),
            .blk_len    (block_len),
            .in_blk     (in_block),
            .in_rdy     (in_ready),
            .out_rdy    (out_ready),
            .blk_type   (block_type),
            .out_blk    (out_block)
        );

        always @(negedge rstn) if (!rstn) in_ready <= 0;
    end

    task process (
        input is_decrypt,
        input[7:0] len,
        input[127:0] blk,
        output[127:0] res
    );
    begin
        block_proc.is_decrypt <= is_decrypt;
        block_proc.block_len <= len;
        block_proc.in_block <= blk;
        block_proc.in_ready <= 1;
        #1 block_proc.in_ready <= 0;
        #1 wait(block_proc.out_ready == 1); //check out_ready for every clock cycle
        res = block_proc.out_block;
    end
    endtask

    localparam[255:0] tcon = 255'h000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f;
    reg[127:0] block, tag;
    reg[255:0] buffer;
    integer i, j, k;
    task test (
        input[7:0] assoc_len,
        input[7:0] text_len
    );
    begin
        $display("Count = %0d", text_len * 33 + assoc_len + 1);
        reset; //encryption
        $display("Key = %h", tcon[128+:128]);
        process(0, 128, tcon[128+:128], block); //key input
        $display("Nonce = %h", tcon[128+:128]); 
        process(0, 128, tcon[128+:128], block); //nonce input
        $write("PT = ");
        for (i = 0; i <  text_len * 8; i = i + 8) $write ("%h", tcon[248 - i +: 8]);
        $write("\nAD = ");
        for (i = 0; i < assoc_len * 8; i = i + 8) $write ("%h", tcon[248 - i +: 8]);
        $write("\nCT = ");
        for (j = 0; j < assoc_len * 8; j = j + 128) begin
            k = assoc_len * 8 - j;
            k = k > 128 ? 128 : k;
            process(0, k, tcon[128 - j +: 128], block); //assiciated data input
        end
        if (assoc_len % 16 == 0) process(0, 0, tcon, block); //associated data finalization
        for (j = 0; j <  text_len * 8; j = j + 128) begin
            k =  text_len * 8 - j;
            k = k > 128 ? 128 : k;
            process(0, k, tcon[128 - j +: 128], block); //plaintext input
            buffer[128 - j +: 128] = block;
        end
        if (text_len % 16 == 0) process(0, 0, tcon, block); //plaintext finalization
        process(0, 0, tcon, block); //get the tag
        tag = block;
        for (i = 0; i <  text_len * 8; i = i + 8) $write ("%h", buffer[248 - i +: 8]);
        $display("%h\n", tag); //display ciphertext and tag
        
        reset; //decryption
        process(1, 128, tcon[128+:128], block); //key input
        process(1, 128, tcon[128+:128], block); //nonce input
        for (j = 0; j < assoc_len * 8; j = j + 128) begin
            k = assoc_len * 8 - j;
            k = k > 128 ? 128 : k;
            process(1, k, tcon[128 - j +: 128], block); //assiciated data input
        end
        if (assoc_len % 16 == 0) process(1, 0, tcon, block); //associated data finalization
        for (j = 0; j <  text_len * 8; j = j + 128) begin
            k =  text_len * 8 - j;
            k = k > 128 ? 128 : k;
            process(1, k, buffer[128 - j +: 128], block); //ciphertext input
            buffer[128 - j +: 128] = block;
        end
        if (text_len % 16 == 0) process(1, 0, tcon, block); //plaintext finalization
        process(1, 0, tcon, block); //get the tag
        if (buffer[248 - text_len +: 256] != tcon[248 - text_len +: 256] || block != tag) begin
            $display("Tag validation error, decryption failed! ");
            $stop;
        end
    end
    endtask
    
    integer assoc_len, text_len;
    initial begin

        for (text_len = 0; text_len <= 32; text_len = text_len + 8)
        for (assoc_len = 0; assoc_len <= 32; assoc_len = assoc_len + 8)
        test(assoc_len, text_len);
        
        $finish;

    end

endmodule
