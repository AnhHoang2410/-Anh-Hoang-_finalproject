module bitcoin_hash(	input logic clk, reset_n, start,
								input logic [15:0] message_addr, output_addr,
								output logic done, mem_clk, mem_we,
								output logic [15:0] mem_addr,
								output logic [31:0] mem_write_data,
								input logic [31:0] mem_read_data);


assign mem_clk= clk;								
enum logic [3:0] {IDLE, STEP1, STEP2, STEP3,STEP1b, STEP2b, STEP3b, STEP2c, STEP3c, COMPUTE1, COMPUTE2, COMPUTE3, PRE, WRITE} state;
							
// SHA256 K constants
parameter int k[0:63] = '{
   32'H428a2f98,32'H71374491,32'Hb5c0fbcf,32'He9b5dba5,32'H3956c25b,32'H59f111f1,32'H923f82a4,32'Hab1c5ed5,
   32'Hd807aa98,32'H12835b01,32'H243185be,32'H550c7dc3,32'H72be5d74,32'H80deb1fe,32'H9bdc06a7,32'Hc19bf174,
   32'He49b69c1,32'Hefbe4786,32'H0fc19dc6,32'H240ca1cc,32'H2de92c6f,32'H4a7484aa,32'H5cb0a9dc,32'H76f988da,
   32'H983e5152,32'Ha831c66d,32'Hb00327c8,32'Hbf597fc7,32'Hc6e00bf3,32'Hd5a79147,32'H06ca6351,32'H14292967,
   32'H27b70a85,32'H2e1b2138,32'H4d2c6dfc,32'H53380d13,32'H650a7354,32'H766a0abb,32'H81c2c92e,32'H92722c85,
   32'Ha2bfe8a1,32'Ha81a664b,32'Hc24b8b70,32'Hc76c51a3,32'Hd192e819,32'Hd6990624,32'Hf40e3585,32'H106aa070,
   32'H19a4c116,32'H1e376c08,32'H2748774c,32'H34b0bcb5,32'H391c0cb3,32'H4ed8aa4a,32'H5b9cca4f,32'H682e6ff3,
   32'H748f82ee,32'H78a5636f,32'H84c87814,32'H8cc70208,32'H90befffa,32'Ha4506ceb,32'Hbef9a3f7,32'Hc67178f2
};

//parameter NUM_NONCES = 16;

logic [6:0]t;
logic [31:0] a,b,c,d,e,f,g,h;//intermediated HasH block
logic [31:0] H0, H1, H2, H3, H4, H5, H6, H7;
logic [31:0] B0,B1,B2,B3,B4,B5,B6,B7;
logic [31:0] A[8];//original mux of 1:16
logic [31:0] w[16];
logic [31:0] rc; // read
logic [3:0] nc;
logic [31:0] temp;// pre compute value

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

function logic [31:0] wtnew; // function witH no inputs
 logic [31:0] s0, s1;
 s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
 s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
 wtnew = w[0] + s0 + w[9] + s1;
endfunction

				
always_ff @(posedge clk, negedge reset_n) 
	begin
	
	$display(" wt: %h, t: %d nc:%d H0:%h H1:%h H2:%h H3:%h H4:%h H5:%h H6:%h H7:%h ",w[15],t,nc, H0+a,H1,H2,H3,H4,H5,H6,H7);

    if (!reset_n) begin
    	state <= IDLE;	
		done<=0;		
    end else 
    case (state)
    	IDLE: begin // start
        	if (start) begin 
            mem_we <= 0;
				mem_addr <= message_addr;//read0
				rc<=1;
				nc<= 0;
				{H0, H1, H2, H3, H4, H5, H6, H7} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
				state <= STEP1;
			end
		end	
		
		
		STEP1: begin 
         mem_addr <= message_addr+rc;//read1
			rc<=rc+1;
			state <= STEP2;	  
		end	
		
		STEP2: begin // precompute
			t <= 0;
			w[15]<=mem_read_data; //w0
			mem_addr <= message_addr+rc;//read2
			rc<=rc+1;
			state <= STEP3;
			{a,b,c,d,e,f,g,h} <= {H0, H1, H2, H3, H4, H5, H6, H7};							
			
		end		
		
		STEP3: begin // read and precompute w[t]
         temp <= w[15]+k[t]+h;// temp0
			for(int n=0; n<15;n ++) w[n] <= w[n+1];//swap		
			w[15]<=mem_read_data; //w0
			mem_addr <= message_addr+ rc;//read3
			rc<=rc+1;
			t<=t+1;
			state <= COMPUTE1;
		end
		
		COMPUTE1: begin
			if(t<65)begin
				for(int n=0; n<15;n ++) w[n] <= w[n+1];
				if(t<15) begin
					w[15] <=mem_read_data;
					mem_addr <= message_addr+rc;//read 4
					rc<=rc+1;
				end else begin
					w[15] <=wtnew();
					mem_addr <= message_addr+16;//read 4
					rc<=17;
				end
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, temp); // calculate a,b,...H
				t<=t+1;
				temp<= w[15]+k[t]+g;
				state<=COMPUTE1;
			end else begin // t>63
				{B0,B1,B2,B3,B4,B5,B6,B7}<={H0 + a,H1 +b,H2 +c,H3 + d,H4 + e,H5 + f,H6 + g,H7 +h};
				state<=STEP1b;
			end	
		end

		STEP1b:begin
		{H0,H1,H2,H3,H4,H5,H6,H7}<={B0,B1,B2,B3,B4,B5,B6,B7};
		mem_addr <= message_addr+rc;//read2
		rc<=rc+1;
		state <= STEP2b;
		end
		
		STEP2b: begin // precompute
			w[15]<=mem_read_data; //w0
			mem_addr <= message_addr+rc;//read2
			rc<=rc+1;
			for (int n = 0; n < 15; n++) w[n] <= w[n+1];			
			t <= 0;
			{a,b,c,d,e,f,g,h}<={H0,H1,H2,H3,H4,H5,H6,H7};
			state <= STEP3b;			
		end		
		
		STEP3b: begin // read and precompute w[t]
         	temp <= w[15]+k[t]+h;// temp0
			for(int n=0; n<15;n ++) w[n] <= w[n+1];//swap		
			w[15]<=mem_read_data; //w0
			mem_addr <= message_addr+ rc;//read3
			rc<=rc+1;
			state<=COMPUTE2;
			t<=t+1;
		end
			
		COMPUTE2:begin// phase 2
			if(t<65)begin // use t as a counter
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, temp); // calculate a,b,...H
				temp<= w[15]+k[t]+g;				
				for(int n=0; n<15;n ++) w[n] <= w[n+1];
				if(t<2) begin w[15] <=mem_read_data;
				mem_addr <= message_addr+rc;
				rc<=rc+1;
				end else if(t==2) w[15] <= nc;
				else if(t==3) w[15] <=32'h80000000;
				else if(t<14) w[15] <= 32'h00000000;
				else if(t==14) w[15]<=32'h00000280;					
				else w[15]<=wtnew();
				t<=t+1;
				state<=COMPUTE2;
			end else begin // t>63
				{A[0], A[1], A[2], A[3], A[4], A[5], A[6], A[7]} <= {H0 + a, H1 + b, H2 + c, H3 + d, H4 + e, H5 + f, H6 + g, H7 + h};					
            	{H0, H1, H2, H3, H4, H5, H6, H7} <= {32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a, 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
				t<=0;
				state<=STEP2c;
			 end // dont witH t>63 
		end 
		
		STEP2c: begin // precompute
			w[15]<=A[t]; //w0
			{a,b,c,d,e,f,g,h}<={H0,H1,H2,H3,H4,H5,H6,H7};
			state <= STEP3c;			
		end		
		
		STEP3c: begin // read and precompute w[t]
         	temp <= w[15]+k[t]+h;// temp0
			for(int n=0; n<15;n ++) w[n] <= w[n+1];//swap		
			w[15]<=A[t+1];
			t<=t+1;
			state<=COMPUTE3;
		end
		
		COMPUTE3:begin
			if(t<65)begin // 
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, temp); // calculate a,b,...H
				temp<= w[15]+k[t]+g;// already add 1 
				for(int n=0; n<15;n ++) w[n] <= w[n+1];
				if(t<7) w[15]=A[t+1];
				else if(t==7) w[15] <=32'h80000000;
				else if(t>7 && t<14) w[15] <= 32'h00000000;
				else if(t==14) w[15]<=32'h00000100;
				else w[15]<=wtnew();
				t<=t+1;
				state<=COMPUTE3;
			end else begin // t>64
            mem_we<=1;
				mem_addr<=output_addr+nc;
				mem_write_data <= H0+a;
				rc<=16;
				state <= WRITE;					
			end //done witH t>64
		end // done witH 3tH pHase	
		
		WRITE: begin
			if (nc< 15) begin
				state <= STEP1b;// need extra step to precompute value for phase 2
				nc<=nc+1;
				mem_we <= 0;
				mem_addr <= message_addr + rc;
				rc<=rc+1;
			end else begin // this is over!!!!!!!!!!!!!!!
				state <= IDLE;
				done <= 1;
			end
			 
		end
		
	endcase
 end
endmodule
			


