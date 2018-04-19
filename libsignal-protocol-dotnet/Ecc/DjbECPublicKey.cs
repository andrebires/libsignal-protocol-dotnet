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

using System;
using System.Linq;
using Libsignal.Util;

namespace Libsignal.Ecc
{
    public class DjbEcPublicKey : IEcPublicKey
    {
        private readonly byte[] _publicKey;

        public DjbEcPublicKey(byte[] publicKey)
        {
            _publicKey = publicKey;
        }


        public byte[] Serialize()
        {
            byte[] type = { (byte)Curve.DjbType };
            return ByteUtil.Combine(type, _publicKey);
        }


        public int GetKeyType()
        {
            return Curve.DjbType;
        }


        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is DjbEcPublicKey)) return false;

            DjbEcPublicKey that = (DjbEcPublicKey)other;
            return Enumerable.SequenceEqual(_publicKey, that._publicKey);
        }


        public override int GetHashCode()
        {
            return string.Join(",", _publicKey).GetHashCode();
        }


        public int CompareTo(Object another)
        {
            byte[] theirs = ((DjbEcPublicKey)another)._publicKey;
            String theirString = string.Join(",", theirs.Select(y => y.ToString()));
            String ourString = string.Join(",", _publicKey.Select(y => y.ToString()));
            return ourString.CompareTo(theirString);
        }

        public byte[] GetPublicKey()
        {
            return _publicKey;
        }

    }
}
