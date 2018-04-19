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

using Libsignal.Util;

namespace Libsignal.Kdf2
{
    public class DerivedRootSecrets
    {
        public static readonly int Size = 64;

        private readonly byte[] _rootKey;
        private readonly byte[] _chainKey;

        public DerivedRootSecrets(byte[] okm)
        {
            byte[][] keys = ByteUtil.Split(okm, 32, 32);
            _rootKey = keys[0];
            _chainKey = keys[1];
        }

        public byte[] GetRootKey()
        {
            return _rootKey;
        }

        public byte[] GetChainKey()
        {
            return _chainKey;
        }
    }
}
