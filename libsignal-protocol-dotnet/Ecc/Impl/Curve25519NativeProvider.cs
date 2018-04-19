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

using System;

namespace Libsignal.Ecc.Impl
{
	class Curve25519NativeProvider : ICurve25519Provider
	{
		//private curve25519.Curve25519Native native = new curve25519.Curve25519Native();

		public byte[] CalculateAgreement(byte[] ourPrivate, byte[] theirPublic)
		{
            throw new NotImplementedException();
        }

		public byte[] CalculateSignature(byte[] random, byte[] privateKey, byte[] message)
		{
            throw new NotImplementedException();
        }

        public byte[] CalculateVrfSignature(byte[] privateKey, byte[] message)
        {
            throw new NotImplementedException();
        }

        public byte[] GeneratePrivateKey(byte[] random)
		{
            throw new NotImplementedException();
        }

		public byte[] GeneratePublicKey(byte[] privateKey)
		{
            throw new NotImplementedException();
        }

		public bool IsNative()
		{
            throw new NotImplementedException();
        }

		public bool VerifySignature(byte[] publicKey, byte[] message, byte[] signature)
		{
            throw new NotImplementedException();
        }

        public byte[] VerifyVrfSignature(byte[] publicKey, byte[] message, byte[] signature)
        {
            throw new NotImplementedException();
        }
    }
}
