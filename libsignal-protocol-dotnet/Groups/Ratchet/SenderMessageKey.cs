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

using System.Text;
using Libsignal.Kdf2;
using Libsignal.Util;

namespace Libsignal.Groups.Ratchet
{
    /**
     * The final symmetric material (IV and Cipher Key) used for encrypting
     * individual SenderKey messages.
     *
     * @author 
     */
    public class SenderMessageKey
    {

        private readonly uint _iteration;
        private readonly byte[] _iv;
        private readonly byte[] _cipherKey;
        private readonly byte[] _seed;

        public SenderMessageKey(uint iteration, byte[] seed)
        {
            byte[] derivative = new HkdFv3().DeriveSecrets(seed, Encoding.UTF8.GetBytes("WhisperGroup"), 48);
            byte[][] parts = ByteUtil.Split(derivative, 16, 32);

            _iteration = iteration;
            _seed = seed;
            _iv = parts[0];
            _cipherKey = parts[1];
        }

        public uint GetIteration()
        {
            return _iteration;
        }

        public byte[] GetIv()
        {
            return _iv;
        }

        public byte[] GetCipherKey()
        {
            return _cipherKey;
        }

        public byte[] GetSeed()
        {
            return _seed;
        }
    }
}
