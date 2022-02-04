// @file run-bfvrns-b.cpp - benchmark for BFVrnsB
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*
BFV RNS testing programs
*/

#define PROFILE

#include <iostream>

#include "palisade.h"
#include "scheme/bfvrns/cryptocontext-bfvrns.h"
#include "gen-cryptocontext.h"
#include "utils/parallel.h"

typedef std::numeric_limits<double> dbl;

using namespace std;
using namespace lbcrypto;

// Poly tests
void SHERun();

int main() {
  SHERun();

  // cin.get();
  return 0;
}

void SHERun() {
  std::cerr << "Running with " << ParallelControls::GetNumProcs()
            << " processors and " << ParallelControls().GetNumThreads()
            << " threads. " << std::endl;

  std::cout << "\n===========BENCHMARKING FOR BFVRNS-B===============: "
            << std::endl;

  std::cout << "\nThis code demonstrates the use of the BFV-RNS scheme for "
               "basic homomorphic encryption operations. "
            << std::endl;
  std::cout
      << "This code shows how to auto-generate parameters during run-time "
         "based on desired plaintext moduli and security levels. "
      << std::endl;
  std::cout << "In this demonstration we use three input plaintext and show "
               "how to both add them together and multiply them together. "
            << std::endl;

  size_t count = 100;

  CCParams<CryptoContextBFVRNS> parameters;
  parameters.SetPlaintextModulus(2);
  parameters.SetRootHermiteFactor(1.0048);
  parameters.SetStandardDeviation(3.2);
  parameters.SetEvalMultCount(5);
  parameters.SetMaxDepth(3);
  parameters.SetScalingFactorBits(55);
  parameters.SetMultiplicationTechnique(BEHZ);

  CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
  // enable features that you wish to use
  cryptoContext->Enable(PKE);
  cryptoContext->Enable(KEYSWITCH);
  cryptoContext->Enable(LEVELEDSHE);

  std::cout << "p = "
            << cryptoContext->GetCryptoParameters()->GetPlaintextModulus()
            << std::endl;
  std::cout << "n = "
            << cryptoContext->GetCryptoParameters()
                       ->GetElementParams()
                       ->GetCyclotomicOrder() /
                   2
            << std::endl;
  std::cout << "log2 q = "
            << cryptoContext->GetCryptoParameters()
                   ->GetElementParams()
                   ->GetModulus()
                   .GetMSB()
            << std::endl;

  // Initialize Public Key Containers
  KeyPair<DCRTPoly> keyPair;

  ////////////////////////////////////////////////////////////
  // Perform Key Generation Operation
  ////////////////////////////////////////////////////////////

  std::cout << "Running key generation (used for source data)..." << std::endl;

  double start = currentDateTime();

  keyPair = cryptoContext->KeyGen();

  double finish = currentDateTime();
  double diff = finish - start;
  cout << "Key generation time: "
       << "\t" << diff << " ms" << endl;

  if (!keyPair.good()) {
    std::cout << "Key generation failed!" << std::endl;
    exit(1);
  }

  cryptoContext->EvalMultKeyGen(keyPair.secretKey);

  ////////////////////////////////////////////////////////////
  // Encode source data
  ////////////////////////////////////////////////////////////

  std::vector<int64_t> vectorOfInts1 = {1, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext1 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts1);

  std::vector<int64_t> vectorOfInts2 = {1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0};
  Plaintext plaintext2 = cryptoContext->MakeCoefPackedPlaintext(vectorOfInts2);

  double timeDecrypt(0.0);
  double timeMult(0.0);
  double timeRelin(0.0);

  for (size_t k = 0; k < count; k++) {
    TimeVar tDecrypt;
    TimeVar tMult;
    TimeVar tRelin;

    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);

    Plaintext plaintextDec1;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext1, &plaintextDec1);

    Plaintext plaintextDec2;
    TIC(tDecrypt);
    cryptoContext->Decrypt(keyPair.secretKey, ciphertext2, &plaintextDec2);
    timeDecrypt += TOC_US(tDecrypt);

    TIC(tMult);
    auto ciphertextMul =
        cryptoContext->EvalMultNoRelin(ciphertext1, ciphertext2);
    timeMult += TOC_US(tMult);

    TIC(tRelin);
    auto ciphertextMulRelin = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    timeRelin += TOC_US(tRelin);
  }

  std::cout << "Average decryption time:\t" << timeDecrypt / (1000 * count)
            << " ms" << std::endl;
  std::cout << "Average multiplication time:\t" << timeMult / (1000 * count)
            << " ms" << std::endl;
  std::cout << "Average relinearization time:\t"
            << (timeRelin - timeMult) / (1000 * count) << " ms" << std::endl;
  std::cout << "Average multiplication + relinearization time:\t"
            << timeRelin / (1000 * count) << " ms" << std::endl;
}
