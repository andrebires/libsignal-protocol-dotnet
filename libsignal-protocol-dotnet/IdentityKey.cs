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
using Libsignal.Ecc;

namespace Libsignal
{
    /**
     * A class for representing an identity key.
     * 
     * @author Moxie Marlinspike
     */

    public class IdentityKey
    {

        private IEcPublicKey _publicKey;

        public IdentityKey(IEcPublicKey publicKey)
        {
            _publicKey = publicKey;
        }

        public IdentityKey(byte[] bytes, int offset)
        {
            _publicKey = Curve.DecodePoint(bytes, offset);
        }

        public IEcPublicKey GetPublicKey()
        {
            return _publicKey;
        }

        public byte[] Serialize()
        {
            return _publicKey.Serialize();
        }

        public String GetFingerprint()
        {
            return _publicKey.Serialize().ToString(); //Hex
        }

        public override bool Equals(Object other)
        {
            if (other == null) return false;
            if (!(other is IdentityKey)) return false;

            return _publicKey.Equals(((IdentityKey)other).GetPublicKey());
        }


        public override int GetHashCode()
        {
            return _publicKey.GetHashCode();
        }
    }
}
