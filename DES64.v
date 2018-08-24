//Controller module to generate to input plain text and key and generate final cipher
module des(finalCipher,plain,key);
  output [63:0]finalCipher;
  input [63:0]plain;
  input[63:0]key;
  wire [63:0]initialPlain;
  wire [63:0]cipher[1:17];
  wire [55:0]initialKey;
  wire [55:0]nextRoundKey[1:16];
  wire [47:0]keyOut[1:16];
  
  initialPermutation iP(initialPlain,plain);
  initialKeyPermutation iKP(initialKey,key);
  
  keyGenerator kG1(nextRoundKey[1],keyOut[1],initialKey,1);
  feistelRound f1(finalCipher,initialPlain,keyOut[1]);
  
  keyGenerator kG2(nextRoundKey[2],keyOut[2],nextRoundKey[1],2);
  feistelRound f2(cipher[2],cipher[1],keyOut[2]);
  
  keyGenerator kG3(nextRoundKey[3],keyOut[3],nextRoundKey[2],3);
  feistelRound f3(cipher[3],cipher[2],keyOut[3]);
  
  keyGenerator kG4(nextRoundKey[4],keyOut[4],nextRoundKey[3],4);
  feistelRound f4(cipher[4],cipher[3],keyOut[4]);
  
  keyGenerator kG5(nextRoundKey[5],keyOut[5],nextRoundKey[4],5);
  feistelRound f5(cipher[5],cipher[4],keyOut[5]);
  
  keyGenerator kG6(nextRoundKey[6],keyOut[6],nextRoundKey[5],6);
  feistelRound f6(cipher[6],cipher[5],keyOut[6]);
  
  keyGenerator kG7(nextRoundKey[7],keyOut[7],nextRoundKey[6],7);
  feistelRound f7(cipher[7],cipher[6],keyOut[7]);
  
  keyGenerator kG8(nextRoundKey[8],keyOut[8],nextRoundKey[7],8);
  feistelRound f8(cipher[8],cipher[7],keyOut[8]);
  
  keyGenerator kG9(nextRoundKey[9],keyOut[9],nextRoundKey[8],9);
  feistelRound f9(cipher[9],cipher[8],keyOut[9]);
  
  keyGenerator kG10(nextRoundKey[10],keyOut[10],nextRoundKey[9],10);
  feistelRound f10(cipher[10],cipher[9],keyOut[10]);
  
  keyGenerator kG11(nextRoundKey[11],keyOut[11],nextRoundKey[10],11);
  feistelRound f11(cipher[11],cipher[10],keyOut[11]);
  
  keyGenerator kG12(nextRoundKey[12],keyOut[12],nextRoundKey[11],12);
  feistelRound f12(cipher[12],cipher[11],keyOut[12]);
  
  keyGenerator kG13(nextRoundKey[13],keyOut[13],nextRoundKey[12],13);
  feistelRound f13(cipher[13],cipher[12],keyOut[13]);
  
  keyGenerator kG14(nextRoundKey[14],keyOut[14],nextRoundKey[13],14);
  feistelRound f14(cipher[14],cipher[13],keyOut[14]);
  
  keyGenerator kG15(nextRoundKey[15],keyOut[15],nextRoundKey[14],15);
  feistelRound f15(cipher[15],cipher[14],keyOut[15]);
  
  keyGenerator kG16(nextRoundKey[16],keyOut[16],nextRoundKey[15],16);
  feistelRound f16(cipher[16],cipher[15],keyOut[16]);
  
  assign cipher[17]={cipher[16][31:0],cipher[16][63:32]};
  finalPermutation fP(finalCipher,cipher[17]);
  
  
endmodule

/*END*/

/*Definition of Feistel Rounds*/  
  
module feistelRound(cipher,plain,key);
  input [63:0]plain;
  input [47:0]key;
  output [63:0]cipher;
  wire [31:0]inExp,s,out;
  wire [47:0]x,perm;
  
  assign  cipher[63:32]=plain[31:0];
  plainExpPermutation pEP0(perm,plain[31:0]);
  assign x=perm^key;
  
  s1_box s1(s[31:28],x[47:42]);
  s2_box s2(s[27:24],x[41:36]);
  s3_box s3(s[23:20],x[35:30]);
  s4_box s4(s[19:16],x[29:24]);
  s5_box s5(s[15:12],x[23:18]);
  s6_box s6(s[11:8],x[17:12]);
  s7_box s7(s[7:4],x[11:6]);
  s8_box s8(s[3:0],x[5:0]);
  plainRightPermutation pRP(out,s);
  assign cipher[31:0]=out^plain[63:32];
 
endmodule
  


/*Plaintext Permutations*/
  
module initialPermutation(cipher,plain);
  output reg [63:0]cipher;
  input [63:0]plain;
  integer i,j,k;
  
  always@(*)
    begin
      for(i=57,k=0;i<=63;i=i+2)
        begin
          for(j=i;j>=i-56;j=j-8,k=k+1)
            begin
              cipher[k]=plain[j];
            end
        end
      for(i=56;i<=62;i=i+2)
        begin
          for(j=i;j>=i-56;j=j-8,k=k+1)
            begin
              cipher[k]=plain[j];
            end
        end
    end
endmodule


module finalPermutation(cipher,plain);
  output reg [63:0]cipher;
  input [63:0]plain;
  integer i,c;
  
  always@(*)
    begin
      for(i=39,c=0;i>=32;i=i-1,c=c+1)
        cipher[0+c*8]=plain[i];
      
      for(i=7,c=0;i>=0;i=i-1,c=c+1)
          cipher[1+c*8]=plain[i];
 
      for(i=47,c=0;i>=40;i=i-1,c=c+1)
          cipher[2+c*8]=plain[i];
      
      for(i=15,c=0;i>=8;i=i-1,c=c+1)
          cipher[3+c*8]=plain[i];
      
      for(i=55,c=0;i>=48;i=i-1,c=c+1)
          cipher[4+c*8]=plain[i];
      
      for(i=24,c=0;i>=16;i=i-1,c=c+1)
          cipher[5+c*8]=plain[i];
      
      for(i=63,c=0;i>=56;i=i-1,c=c+1)
          cipher[6+c*8]=plain[i];
      
      for(i=31,c=0;i>=24;i=i-1,c=c+1)
          cipher[7+c*8]=plain[i];
     
    end
endmodule


module plainExpPermutation(out,rightBits);
  output reg [47:0]out;
  input [31:0]rightBits;
  integer i,j,k;
  
  always@(*)
    begin
      for(i=0;i<9;i++)
        begin
          for(j=0;j<4;j++)
            begin
              out[1+6*i+j]=rightBits[4*i+j];
            end
        end
      out[0]=rightBits[31];
      for(i=1;i<=7;i=i++)
        begin
          out[6*i]=rightBits[4*i-1];
        end
      for(i=0;i<7;i++)
        begin
          out[5+i*6]=rightBits[4+i*4];
        end
      out[47]=rightBits[0];
      end
  
endmodule



module plainRightPermutation(out,expBits);
  input [31:0]expBits;
  output reg[31:0]out;
  integer b[0:31];
  integer i;
  
  assign b={16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
  
  always@(*)
    begin
      for(i=0;i<32;i++)
        out[i]=expBits[b[i]-1];
    end
endmodule



/*Plaintext Permutations*/



/*Key Expansion and Permutation*/



module initialKeyPermutation(keyOut,keyIn);
  output reg [55:0]keyOut;
  input [63:0]keyIn;
  integer pTable[0:55];
  integer i;
  
  assign pTable={57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
  
  always@(*)
    begin
      for(i=0;i<56;i++)
        keyOut[i]=keyIn[pTable[i]-1];
    end
endmodule


module keyLeftShift(C_out,D_out,round,C_in,D_in);
  input [27:0]C_in,D_in;
  output reg [27:0]C_out,D_out;
  input integer round;
  integer shiftTable[1:16];
  integer shift;
  
  assign shiftTable={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
  assign shift=shiftTable[round];
  
  always@(*)
    begin
      if(shift==1)
        begin
          C_out={C_in[26:0],C_in[27]};
          D_out={D_in[26:0],D_in[27]};
        end
      else
        begin
          C_out={C_in[25:0],C_in[27:26]};
          D_out={D_in[25:0],D_in[27:26]};
        end
      end
  initial
    begin
      #1 $display("%b",{C_out,D_out});
    end
  
  
endmodule


module finalKeyPermutation(keyOut,keyIn);
  input [55:0]keyIn;
  output reg[47:0]keyOut;
  integer i;
  integer pTable[0:47];
  
  assign pTable={14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
  always@(*)
    begin
      for(i=0;i<48;i++)
        keyOut[i]=keyIn[pTable[i]-1];
    end
endmodule
  

module keyGenerator(nextRoundKey,keyOut,keyIn,round);
  input[55:0]keyIn;
  input integer round;
  output [55:0]nextRoundKey;
  reg [55:0]dKey;
  output [47:0]keyOut;
  wire [27:0]C_out,D_out;
  
  keyLeftShift kLS(C_out,D_out,round,keyIn[55:28],keyIn[27:0]);
  assign nextRoundKey={C_out,D_out};
     
  finalKeyPermutation fkP(keyOut,{C_out,D_out});
  initial
    begin
      #1 $display("%b",keyOut);
    end
  
endmodule
        

/*Key Expansion and Permutation*/
  
  
  
  
/*Definition of S boxes*/  


module s1_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s1_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s1_box_table[0]={14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7};
  assign s1_box_table[1]={0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8};
  assign s1_box_table[2]={4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0};
  assign s1_box_table[3]={15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
 
  assign out=s1_box_table[outward_bits][inward_bits];
endmodule




module s2_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s2_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s2_box_table[0]={15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10};
  assign s2_box_table[1]={3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5};
  assign s2_box_table[2]={0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15};
  assign s2_box_table[3]={13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s2_box_table[outward_bits][inward_bits];
endmodule


module s3_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s3_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s3_box_table[0]={10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8};
  assign s3_box_table[1]={13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1};
  assign s3_box_table[2]={13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7};
  assign s3_box_table[3]={1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s3_box_table[outward_bits][inward_bits];
endmodule



module s4_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s4_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s4_box_table[0]={7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15};
  assign s4_box_table[1]={13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9};
  assign s4_box_table[2]={10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4};
  assign s4_box_table[3]={3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s4_box_table[outward_bits][inward_bits];
endmodule



module s5_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s5_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s5_box_table[0]={2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9};
  assign s5_box_table[1]={14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6};
  assign s5_box_table[2]={4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14};
  assign s5_box_table[3]={11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s5_box_table[outward_bits][inward_bits];
endmodule




module s6_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s6_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s6_box_table[0]={12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11};
  assign s6_box_table[1]={10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8};
  assign s6_box_table[2]={9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6};
  assign s6_box_table[3]={4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s6_box_table[outward_bits][inward_bits];
endmodule




module s7_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s7_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s7_box_table[0]={4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1};
  assign s7_box_table[1]={13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6};
  assign s7_box_table[2]={1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2};
  assign s7_box_table[3]={6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s7_box_table[outward_bits][inward_bits];
endmodule




module s8_box(out,in);
  output [3:0]out;
  input [5:0]in;
  integer s8_box_table[0:3][0:15];
  integer outward_bits,inward_bits;
  
  assign s8_box_table[0]={13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7};
  assign s8_box_table[1]={1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2};
  assign s8_box_table[2]={7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8};
  assign s8_box_table[3]={2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11};
  
  assign outward_bits={in[5],in[0]};
  assign inward_bits=in[4:1];
  
  
  assign out=s8_box_table[outward_bits][inward_bits];
endmodule


/*Definition of S boxes*/ 
                          
  

  
    
  
  
  
