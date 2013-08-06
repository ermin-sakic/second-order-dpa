Second Order Differential Power Analysis
================

### Introduction:
In order to test the enhanced AES procedure, extended by masking and shuffling security measures, 
the second order differential power analysis (DPA), adapted from the 1 and 2, was implemented and 
executed. Compared to the normal DPA, the second order DPA makes use of two points in the 
trace array instead of one, combines them with a preprocessing function, in order to expose 
correlation of these points with the, later created, Hamming weight matrix consisting of hypothetical 
intermediate state values. 

### Attack description:

Two attack possibilities exist, attacking either one or two masked table 
look-ups. In order to attack only one masked output, the masked input needs to be known as well, and the 
input and output masks of the S-Box need to be equal in order to cancel each other out. The second solution 
combines two S-Box outputs, so that two key bytes need to be guessed and taken into consideration 
(65536 combinations). For the preprocessing function, we have chosen the, in the literature recommended, 
absolute difference, which in the case of a 1-bit scenario results with the highest correlation value of 1. 
In case of an 8-bit scenario, the highest possible achievable correlation with the matrix of hypothetical 
intermediate value vectors is 0,24. In our case, the S-Box lookups in the last round were targeted as the 
vulnerable spot. The masked S-Box is implemented as `S_m(P⊕K_2⊕M) = Inv_S(P⊕K_2) + M'`, where K_2 represents the key generated for the second round of the AES encryption procedure 
(10th round key of the AES decryption procedure).

In an ideal case, we were hoping that the use of the absolute difference, when combining each point in 
the power trace matrix with the all other points would at least once result with the masks canceling 
each other. For this to work, we had to assume that the secure implementation uses the same values 
for M and M' for the testing/attacking simplifications.

The searched combination in the preprocessing matrix is represented by the difference 
`|C(Inv_S(P⊕K_2)⊕M)−C(P⊕K_2⊕M)|` which in turn correlates with Hamming weights of the guessed 
and backwards-computed pair `HW(S(C⊕K_1)⊕(C⊕K_1))`. Here, the guessed value `C⊕K_1` 
represents the S-Box output `Inv_S(P⊕K_2)` and `S(C⊕K_1)` represents the S-Box input `P⊕K_2` in the 
decrpytion phase, if a correct key hypothesis was used. Therefore, only one byte of the plaintext 
would need to be used and one byte of the key would need to be guessed. The size of the preprocessing 
matrix equals the number of traces multiplied by `l*(l-1)/2` possible combinations. The matrix consisting 
of hypothetical intermediate values equals the number of cyphertexts multiplied by the 256 possible 
key candidates.

After setting up the matrix of hypothetical intermediate values `addRoundKey -> ShiftRows -> SubBytes`, 
executing the exclusive or (XOR) operation element-wise `S(C⊕K_1)⊕(C⊕K_1)`, the Hamming weights of 
the individual elements need to be computed and correlation of this and the preprocessing matrix
performed (vector-wise). The row in the correlation matrix having the highest overall correlation 
value represents the correct key guess. The same procedure is repeated for the remaining 15 bytes.

### References:
1: Power Analysis Attacks: Revealing the Secrets of Smart Cards; Stefan Mangard, Elisabeth Oswald, Thomas Popp  
2: Practical Second-Order DPA Attacks for Masked Smart Card Implementations of Block Ciphers; Elisabeth Oswald, Stefan Mangard, Christoph Herbst, Stefan Tilich

