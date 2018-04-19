using Google.Protobuf;
using Libsignal.Ecc;
using Libsignal.State;
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

namespace Libsignal
{
    /**
     * Holder for public and private identity key pair.
     *
     * @author
     */
    public class IdentityKeyPair
    {

        private readonly IdentityKey _publicKey;
        private readonly IEcPrivateKey _privateKey;

        public IdentityKeyPair(IdentityKey publicKey, IEcPrivateKey privateKey)
        {
            _publicKey = publicKey;
            _privateKey = privateKey;
        }

        public IdentityKeyPair(byte[] serialized)
        {
            try
            {
                IdentityKeyPairStructure structure = IdentityKeyPairStructure.Parser.ParseFrom(serialized);
                _publicKey = new IdentityKey(structure.PublicKey.ToByteArray(), 0);
                _privateKey = Curve.DecodePrivatePoint(structure.PrivateKey.ToByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new InvalidKeyException(e);
            }
        }

        public IdentityKey GetPublicKey()
        {
            return _publicKey;
        }

        public IEcPrivateKey GetPrivateKey()
        {
            return _privateKey;
        }

        public byte[] Serialize()
        {
            return new IdentityKeyPairStructure
            {
                PublicKey = ByteString.CopyFrom(_publicKey.Serialize()),
                PrivateKey = ByteString.CopyFrom(_privateKey.Serialize())

            }.ToByteArray();
        }
    }
}
