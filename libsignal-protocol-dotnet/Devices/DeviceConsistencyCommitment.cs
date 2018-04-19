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
using System.Security.Cryptography;
using System.Text;
using Libsignal.Util;

namespace Libsignal.Devices
{
    public class DeviceConsistencyCommitment
    {
        private static readonly string Version = "DeviceConsistencyCommitment_V0"; 

        private readonly int _generation;
        private readonly byte[] _serialized;

        public DeviceConsistencyCommitment(int generation, List<IdentityKey> identityKeys)
        {
            try
            {
                List<IdentityKey> sortedIdentityKeys = new List<IdentityKey>(identityKeys);
                sortedIdentityKeys.Sort(new IdentityKeyComparator());

                SHA512 messageDigest = SHA512.Create();
                _serialized = messageDigest.ComputeHash(ByteUtil.Combine(new byte[][]
                    {
                        Encoding.UTF8.GetBytes(Version),
                        ByteUtil.IntToByteArray(generation)
                    }));

                foreach (IdentityKey commitment in sortedIdentityKeys)
                {
                    _serialized = messageDigest.ComputeHash(ByteUtil.Combine(new byte[][]
                        {
                            _serialized,
                            commitment.GetPublicKey().Serialize()
                        }));
                }

                _generation = generation;
            }
            catch (Exception e)
            {
                Debug.Assert(false, e.Message);
                throw e;
            }
        }

        public byte[] ToByteArray()
        {
            return _serialized;
        }

        public int GetGeneration()
        {
            return _generation;
        }
    }
}
