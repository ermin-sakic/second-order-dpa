%{  
       An implementation of the second-order Differential Power 
       Analysis (DPA) attack, suited for evaluations of AES-128 
       algorithm on microcontrollers leaking Hamming Weight power 
       models.


       Authors:: Ermin Sakic, Yigit Dincer
 
       Licensed to the Apache Software Foundation (ASF) under one
       or more contributor license agreements.  See the NOTICE file
       distributed with this work for additional information
       regarding copyright ownership.  The ASF licenses this file
       to you under the Apache License, Version 2.0 (the
       "License"); you may not use this file except in compliance
       with the License.  You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

       Unless required by applicable law or agreed to in writing,
       software distributed under the License is distributed on an
       "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
       KIND, either express or implied.  See the License for the
       specific language governing permissions and limitations
       under the License.
%}

%%--------------- DPA-Attack
clear all;
clc
tic
%% Initialize
load sbox.mat
numTraces = 400;

% number of elements, whose mean should be calculated in order to reduce
% the trace size 
numberMean=50;

% read ciphertext
Cipher=csvread('ciphertext.csv');

% read traces into matlab
load('trace_matrix.mat');

% Read Ciphertext, where first row is unusable
Cipher=Cipher(1:numTraces+1,:);
Cipher(1,:)=[]; 

% Delete first trace, as it can not be used for the attack
Trace=trace_matrix(2:numTraces+1, :);
%% Main

% COMPRESSION
% calculate the mean of Trace for the defined interval above in order to
% compress the data. mean-calculation can be applied to columns quickly in
% MATLAB. So we reshape the trace_matrix and calculate the mean of it, then
% reshape it back.
u=reshape(Trace',numberMean,(size(Trace,2)*size(Trace,1))/numberMean);
u=mean(u);
Trace=reshape(u,size(u,2)/size(Trace,1),size(Trace,1));
Trace=Trace';
plot(Trace(2,:));
% Key vector (repmat command is used to improve calculation speed later)
hypothese =repmat([0:255],[numTraces,1,16]); 

display('Data loaded and compressed.');
toc

lengthvector = size(Trace,2);
clear P;
P = zeros(numTraces, ((lengthvector-1) * lengthvector)/2);  % da |I_a - I_b| = |I_b - I_a| gilt, SQUARED complexity!

e=0;
s=1;
for i=1:lengthvector
    e=s+lengthvector-i-1;
    P(:,s:e) = abs(bsxfun(@minus,Trace(:,(i+1):end),Trace(:,i)));
    s=e+1;
end


display('Preprocessing finished.');
toc

% Reshape D-Matrix in order to avoid any for-loops & do calculations in one
% 3D-Matrix for optimized calculations
manipulatedCipher = reshape(Cipher,numTraces,1,16);
manipulatedCipher = repmat(manipulatedCipher,1,256);

%% Crack the key
% 1) Add round Key
addRoundKey = bitxor(manipulatedCipher, hypothese);

% 2) SubByte, here the output of the SBox operation is estimated
subByte = sbox(addRoundKey+1);

% 3) SubByte, here the input of the SBox operation is estimated
sboxinput = bitxor(subByte, addRoundKey);

% 4) Hamming Distance
Hamming = arrayfun(@(x) sum(bitget(x,1:8)),sboxinput);

display('Hypothetical values calculated.');
toc

clear addRoundKey;
clear subByte;
clear sboxinput;
clear trace_matrix;
clear u;
clear manipulatedCipher;
clear Trace;
% calculate correlationmatrix for each byte
Correlation = zeros(256, size(P,2));
%% Plot
figure;

for i=1:16
    display(['Calculating correlation ' int2str(i)]);
    toc
    Correlation = corr(Hamming(:,:,i),P);
    
    [~, index] = max(abs(Correlation(:)));
    [row(i),column(i)] = ind2sub(size(Correlation),index);
    display(['Row: ' int2str(row(i))]);
    display(['Column: ' int2str(column(i))]);
    display(max(abs(Correlation(:))));

    key = row(:)' -1;
    display(key);
end

% Find maximum values of the correlation matrix
% sizeCorr=size(Correlation);
% reshapedCorrelation = reshape(Correlation, [sizeCorr(1)*sizeCorr(2),1,sizeCorr(3)]);
% [~, index] = max(abs(reshapedCorrelation));
% [row,column] = ind2sub(sizeCorr(1:2),index);

% find the final key
key=row(:)'-1
keyHex= dec2hex(key)

display('finished.');
toc

% test whether if the cracked key is correct
% keyCorrect=min(key==[85 193 121 4 195 220 4 82 42 12 118 239 232 202 72 181])

