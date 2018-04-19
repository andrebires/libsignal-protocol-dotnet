/** 
 * Copyright (C) 2017 golf1052
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
using System.Collections.Generic;
using System.Diagnostics;
using libsignal.util;
using System.Security.Cryptography;

namespace libsignal.devices
{
    public class DeviceConsistencyCodeGenerator
    {
        public const int CodeVersion = 0;
        
        public static string GenerateFor(DeviceConsistencyCommitment commitment, List<DeviceConsistencySignature> signatures)
        {
            try
            {
                List<DeviceConsistencySignature> sortedSignatures = new List<DeviceConsistencySignature>(signatures);
                sortedSignatures.Sort(new SignatureComparator());

                SHA512 messageDigest = SHA512.Create();
                byte[] hash = messageDigest.ComputeHash(ByteUtil.Combine(new byte[][]
                {
                    ByteUtil.ShortToByteArray(CodeVersion),
                    commitment.ToByteArray()
                }));

                foreach (DeviceConsistencySignature signature in sortedSignatures)
                {
                    hash = messageDigest.ComputeHash(ByteUtil.Combine(new byte[][]
                        {
                            hash,
                            signature.GetVrfOutput()
                        }));
                }

                string digits = GetEncodedChunk(hash, 0) + GetEncodedChunk(hash, 5);
                return digits.Substring(0, 6);
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        private static string GetEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.ByteArray5ToLong(hash, offset) % 100000;
            return string.Format("{0:d5}", chunk);
        }
    }

    class SignatureComparator : ByteArrayComparator, IComparer<DeviceConsistencySignature>
    {
        public int Compare(DeviceConsistencySignature first, DeviceConsistencySignature second)
        {
            return Compare(first.GetSignature(), second.GetSignature());
        }
    }
}
