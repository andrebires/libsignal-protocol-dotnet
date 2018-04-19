using System;
using Google.Protobuf;
using Libsignal.Ecc;
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

namespace Libsignal.State
{
    public class PreKeyRecord
    {

        private PreKeyRecordStructure _structure;

        public PreKeyRecord(uint id, EcKeyPair keyPair)
        {
            _structure = new PreKeyRecordStructure
            {
                Id = id,
                PublicKey = ByteString.CopyFrom(keyPair.GetPublicKey().Serialize()),
                PrivateKey = ByteString.CopyFrom(keyPair.GetPrivateKey().Serialize())
            };
        }

        public PreKeyRecord(byte[] serialized)
        {
            _structure = PreKeyRecordStructure.Parser.ParseFrom(serialized);
        }



        public uint GetId()
        {
            return _structure.Id;
        }

        public EcKeyPair GetKeyPair()
        {
            try
            {
                IEcPublicKey publicKey = Curve.DecodePoint(_structure.PublicKey.ToByteArray(), 0);
                IEcPrivateKey privateKey = Curve.DecodePrivatePoint(_structure.PrivateKey.ToByteArray());

                return new EcKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        public byte[] Serialize()
        {
            return _structure.ToByteArray();
        }
    }
}
