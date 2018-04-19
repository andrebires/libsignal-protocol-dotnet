/** 
 * Copyright (C) 2016 smndtrl, langboost
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

using libsignal.util;
using System;
using System.IO;

namespace libsignal.kdf
{
    public abstract class Hkdf
    {

        private static readonly int HashOutputSize = 32;

        public static Hkdf CreateFor(uint messageVersion)
        {
            switch (messageVersion)
            {
                case 2: return new HkdFv2();
                case 3: return new HkdFv3();
                default: throw new Exception("Unknown version: " + messageVersion);
            }
        }

        public byte[] DeriveSecrets(byte[] inputKeyMaterial, byte[] info, int outputLength)
        {
            byte[] salt = new byte[HashOutputSize];
            return DeriveSecrets(inputKeyMaterial, salt, info, outputLength);
        }

        public byte[] DeriveSecrets(byte[] inputKeyMaterial, byte[] salt, byte[] info, int outputLength)
        {
            byte[] prk = Extract(salt, inputKeyMaterial);
            return Expand(prk, info, outputLength);
        }

        private byte[] Extract(byte[] salt, byte[] inputKeyMaterial)
        {
            try
            {
                return Sign.Sha256Sum(salt, inputKeyMaterial);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        private byte[] Expand(byte[] prk, byte[] info, int outputSize)
        {
            try
            {
                int iterations = (int)Math.Ceiling((double)outputSize / (double)HashOutputSize);
                byte[] mixin = new byte[0];
                MemoryStream results = new MemoryStream();
                int remainingBytes = outputSize;

                for (int i = GetIterationStartOffset(); i < iterations + GetIterationStartOffset(); i++)
                {
                    MemoryStream msg = new MemoryStream();
                    msg.Write(mixin, 0, mixin.Length);
                    if (info != null)
                    {
                        msg.Write(info, 0, info.Length);
                    }
                    byte[] ib = BitConverter.GetBytes(i);
                    msg.Write(ib, 0, 1);

                    byte[] stepResult = Sign.Sha256Sum(prk, msg.ToArray());
                    int stepSize = Math.Min(remainingBytes, stepResult.Length);

                    results.Write(stepResult, 0, stepSize);

                    mixin = stepResult;
                    remainingBytes -= stepSize;
                }

                return results.ToArray();
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        protected abstract int GetIterationStartOffset();

    }
}
