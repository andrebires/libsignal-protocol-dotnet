﻿

using Google.Protobuf;
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
using libsignal.ecc;
using System;

namespace libsignal.state
{
    public class SignedPreKeyRecord
    {

        private SignedPreKeyRecordStructure _structure;

        public SignedPreKeyRecord(uint id, ulong timestamp, EcKeyPair keyPair, byte[] signature)
        {
            this._structure = new SignedPreKeyRecordStructure
            {
                Id = id,
                PublicKey = ByteString.CopyFrom(keyPair.GetPublicKey().Serialize()),
                PrivateKey = ByteString.CopyFrom(keyPair.GetPrivateKey().Serialize()),
                Signature = ByteString.CopyFrom(signature),
                Timestamp = timestamp
            };
        }

        public SignedPreKeyRecord(byte[] serialized)
        {
            this._structure = SignedPreKeyRecordStructure.Parser.ParseFrom(serialized);
        }

        public uint GetId()
        {
            return this._structure.Id;
        }

        public ulong GetTimestamp()
        {
            return this._structure.Timestamp;
        }

        public EcKeyPair GetKeyPair()
        {
            try
            {
                IEcPublicKey publicKey = Curve.DecodePoint(this._structure.PublicKey.ToByteArray(), 0);
                IEcPrivateKey privateKey = Curve.DecodePrivatePoint(this._structure.PrivateKey.ToByteArray());

                return new EcKeyPair(publicKey, privateKey);
            }
            catch (InvalidKeyException e)
            {
                throw new Exception(e.Message);
            }
        }

        public byte[] GetSignature()
        {
            return this._structure.Signature.ToByteArray();
        }

        public byte[] Serialize()
        {
            return this._structure.ToByteArray();
        }
    }
}