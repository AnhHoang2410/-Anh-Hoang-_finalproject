module bitcoin_hash (input logic clk, reset_n, start, 
								input logic[15:0] message_addr, output_addr,
								output logic done, mem_clk, mem_we,
								output logic [15:0] mem_addr,
								output logic [31:0] mem_write_data,
								input logic [31:0] mem_read_data);
	assign mem_clk=clk;								
	enum logic[3:0] {IDLE, PRE, START, READ, PRECOMPUTE, COMPUTE, WRITE} state;

	parameter NUM_NONCES = 16;

	logic [7:0] wc, rc, nc;
	logic [7:0] m;
	logic [7:0] t;
	logic [31:0] h[8][NUM_NONCES];
	logic [31:0] w[16][NUM_NONCES];
	logic [31:0] Z[16][NUM_NONCES];
	logic [31:0] A[NUM_NONCES], B[NUM_NONCES], C[NUM_NONCES], D[NUM_NONCES], E[NUM_NONCES], F[NUM_NONCES], G[NUM_NONCES], H[NUM_NONCES];	
	logic [31:0] temp[NUM_NONCES];
	
	parameter int k[0:63] = '{
		32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
		32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
		32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
		32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
		32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
		32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070, 
		32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
		32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
	};

	function logic [31:0] rightrotate(input logic [31:0] x,
								input logic [7:0] r);
		begin
			rightrotate = (x >> r) | (x << (32-r));
		end
	endfunction


	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, temp);
    logic [31:0] S1, S0, cH, maj, t1, t2; // internal signals
	begin
		S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		cH = (e & f) ^ ((~e) & g);
		t1 =  S1 + cH + temp;
		S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = S0 + maj;

		sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	end
	endfunction


	function logic [31:0] wtnew(input logic [3:0] n);
		logic [31:0] s0, s1;
		s0 = rightrotate(w[n][1], 7) ^ rightrotate(w[n][1], 18) ^ (w[n][1]>>3);
		s1 = rightrotate(w[n][14], 17) ^ rightrotate(w[n][14], 19) ^ (w[n][14]>>10);
		wtnew = w[n][0] + s0 + w[n][9] + s1;      
	endfunction

	always_ff @(posedge clk, negedge reset_n)
		begin
			//$display("A[0]: %h, A[1]: %h, A[2]: %h, A[3]: %h, A[4]: %h, A[5]: %h, A[6]: %h, A[7]: %h, temp: %h, t: %d, state: %s",
            //           A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7], temp[0], t, state.name);
			//$display("w[0][15]: %h, w[1][15]: %h, w[2][15]: %h, w[3][15]: %h, w[4][15]: %h, w[5][15]: %h, w[6][15]: %h, w[7][15]: %h, w[8][15]: %h",
			//			w[0][15], w[1][15], w[2][15], w[3][15], w[4][15], w[5][15], w[6][15], w[7][15], w[8][15]);
			if(!reset_n) begin
				state <= IDLE;
			end else case(state)	
				IDLE: begin
					if(start) begin
						mem_we <= 0;
						mem_addr <= message_addr;
						nc <= 0;
						m <= 0;
						rc <= 1;
						wc <= 0;
						t <= 0;
						for (int n = 0; n < NUM_NONCES; n++) begin 
							{h[0][n], h[1][n], h[2][n], h[3][n], h[4][n], h[5][n], h[6][n], h[7][n]} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
							{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
						end
						state <= START;
					end
				end
				PRE: begin
					mem_addr <= message_addr + rc;
					rc <= rc + 1;
					for(int n = 0; n < NUM_NONCES; n++) begin
						if(m == 1) {A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= {h[0][n], h[1][n], h[2][n], h[3][n], h[4][n], h[5][n], h[6][n], h[7][n]}; 
						else {A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
					end
					state <= START;
				end
				START: begin
					mem_addr <= message_addr + rc;
					for(int n = 0; n < NUM_NONCES; n++) begin
						{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= {h[0][n], h[1][n], h[2][n], h[3][n], h[4][n], h[5][n], h[6][n], h[7][n]};
					end
					rc <= rc + 1;
					state <= READ;
				end
				READ: begin
					
					for(int n = 0; n < NUM_NONCES; n++) begin
						if(m!=2) w[n][15] <= mem_read_data;
						if(m == 2) w[n][15] <= Z[8][n];
						//if(m == 2)$display("w[%d][15] <= Z[8][%d]= %h", n, Z[8][n], n);
					end
					mem_addr <= message_addr + rc;
					rc <= rc + 1;
					state <= PRECOMPUTE;
				end
				PRECOMPUTE: begin
					
					for(int n = 0; n < NUM_NONCES; n++) begin
						for(int k = 0; k < 15; k++) w[n][k] <= w[n][k+1];
						temp[n] <= w[n][15] + k[t] + H[n];
						if(m!=2) w[n][15] <= mem_read_data;
						if(m==2) w[n][15] <= Z[9][n];
					end					
					mem_addr <= message_addr + rc;
					rc <= rc + 1;
					state <= COMPUTE;
					
				end
				COMPUTE: begin
					if(m== 0) begin
						if(t < 64) begin
							
							for(int n = 0; n < NUM_NONCES; n++) begin
								temp[n] <= w[n][15] + k[t+1] + G[n];
								for(int k = 0; k < 15; k++) w[n][k] <= w[n][k+1];
								{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= sha256_op(A[n], B[n], C[n], D[n], E[n], F[n], G[n], temp[n]);
							end							
							if(t<16) begin
								if(rc < 18) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= mem_read_data;
								end else begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= wtnew(n);
								end
								mem_addr <= message_addr + rc;
								rc <= rc + 1;
							end else begin
								for(int n = 0; n < NUM_NONCES; n++) begin									
									w[n][15] <= wtnew(n);
								end
							end
							// Bold and brash
							t <= t+1;
							state <= COMPUTE;
						end else begin
							for(int n = 0; n < NUM_NONCES; n++) begin
								{h[0][n], h[1][n], h[2][n], h[3][n], h[4][n], h[5][n], h[6][n], h[7][n]} <= {h[0][n] + A[n], h[1][n] + B[n], h[2][n] + C[n], h[3][n] + D[n], h[4][n] + E[n], h[5][n] + F[n], h[6][n] + G[n], h[7][n] + H[n]};
								{Z[0][n], Z[1][n], Z[2][n], Z[3][n], Z[4][n], Z[5][n], Z[6][n], Z[7][n]} <= {h[0][n] + A[n], h[1][n] + B[n], h[2][n] + C[n], h[3][n] + D[n], h[4][n] + E[n], h[5][n] + F[n], h[6][n] + G[n], h[7][n] + H[n]};	
							end
							t <= 0;
							m <= m + 1;
							rc <= 16;
							state <= PRE;
						end
					end else if ( m == 1) begin
						if(t < 64) begin
							for(int n = 0; n < NUM_NONCES; n++) begin
								temp[n] <= w[n][15] + k[t+1] + G[n];
								for(int k = 0; k < 15; k++) w[n][k] <= w[n][k+1];
								{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= sha256_op(A[n], B[n], C[n], D[n], E[n], F[n], G[n], temp[n]);
							end
							if(t < 16) begin
								if(rc < 21) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= mem_read_data;
								end else if (rc == 21) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= n;
								end else if (rc == 22) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h80000000;
								end else if (rc > 22 && rc < 33) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h00000000;
								end else if (rc == 33) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h00000280;
								end else begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= wtnew(n);
								end
								mem_addr <= message_addr + rc;
								rc <= rc + 1;
							end else begin
								for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= wtnew(n);
							end
							t <= t + 1;
							state <= COMPUTE;
						end else begin
							for(int n = 0; n < NUM_NONCES; n++) begin
								//$display("Z[8][n]: %h, Z[9][n]: %h, Z[10][n]: %h, Z[11][n]: %h, Z[12][n]: %h, Z[13][n]: %h, Z[14][n]: %h, Z[15][n]: %h", h[0][n] + A[n], h[1][n] + B[n], h[2][n] + C[n], h[3][n] + D[n], h[4][n] + E[n], h[5][n] + F[n], h[6][n] + G[n], h[7][n] + H[n]);
								{Z[8][n], Z[9][n], Z[10][n], Z[11][n], Z[12][n], Z[13][n], Z[14][n], Z[15][n]} <= {h[0][n] + A[n], h[1][n] + B[n], h[2][n] + C[n], h[3][n] + D[n], h[4][n] + E[n], h[5][n] + F[n], h[6][n] + G[n], h[7][n] + H[n]};	
								{h[0][n], h[1][n], h[2][n], h[3][n], h[4][n], h[5][n], h[6][n], h[7][n]} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
							end
							t <= 0;
							m <= 2;
							state <= PRE;
						end
					end else begin
						if(t < 64) begin
							for(int n = 0; n < NUM_NONCES; n++) begin
								temp[n] <= w[n][15] + k[t+1] + G[n];
								for(int k = 0; k < 15; k++) w[n][k] <= w[n][k+1];
								{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= sha256_op(A[n], B[n], C[n], D[n], E[n], F[n], G[n], temp[n]);
							end
							if( t < 16) begin
								if(t == 0) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[10][n];
								end else if (t == 1) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[11][n];
								end else if (t == 2) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[12][n];
								end else if ( t == 3) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[13][n];
								end else if ( t == 4) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[14][n];
								end else if (t == 5) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= Z[15][n];
								end else if (t == 6) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h80000000;
								end else if ( t> 6 && t<13) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h00000000;
								end else if (t == 13) begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= 32'h00000100;
								end else begin
									for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= wtnew(n);
								end
							end else begin
								for(int n = 0; n < NUM_NONCES; n++) w[n][15] <= wtnew(n);
							end
							t <= t + 1;
							state <= COMPUTE;
						end else begin
                            if(nc == NUM_NONCES) done <= 1;
                            else begin							
                                mem_addr <= output_addr + nc;
                                mem_we <= 1;
                                wc <= wc + 1;
                                mem_write_data <= h[0][nc] + A[nc];
                                nc <= nc + 1;
                                state <= COMPUTE;
                            end
						end
					end
				end/*
				WRITE: begin
					if (nc == NUM_NONCES) done <= 1;
					else begin
						mem_addr <= output_addr + nc;
						nc <= nc + 1;
						mem_write_data <= h[0][nc] + A[nc];
						state <= WRITE;						
					end 
				end*/
			endcase	 
		end									
endmodule