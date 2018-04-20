/** 
* Copyright (C) 2017 smndtrl, langboost, golf1052
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace Libsignal.Ecc.Impl
{
    class Curve25519ManagedProvider : ICurve25519Provider
    {
        private readonly org.whispersystems.curve25519.Curve25519 _curve;
        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="type">Such as Curve25519.CSHARP or Curve25519.BEST</param>
        public Curve25519ManagedProvider(string type)
        {
            _curve = org.whispersystems.curve25519.Curve25519.getInstance(type);
        }

        public byte[] CalculateAgreement(byte[] ourPrivate, byte[] theirPublic)
        {
            return _curve.calculateAgreement(theirPublic, ourPrivate);
        }

        public byte[] CalculateSignature(byte[] random, byte[] privateKey, byte[] message)
        {
            return _curve.calculateSignature(random, privateKey, message);
        }

        public byte[] CalculateVrfSignature(byte[] privateKey, byte[] message)
        {
            return _curve.calculateVrfSignature(privateKey, message);
        }

        public byte[] GeneratePrivateKey(byte[] random)
        {
            return _curve.generatePrivateKey(random);
        }

        public byte[] GeneratePublicKey(byte[] privateKey)
        {
            return _curve.generatePublicKey(privateKey);
        }

        public bool IsNative()
        {
            return _curve.isNative();
        }

        public bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return _curve.verifySignature(publicKey, message, signature);
        }

        public byte[] VerifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            return _curve.verifyVrfSignature(publicKey, message, signature);
        }
    }
}
