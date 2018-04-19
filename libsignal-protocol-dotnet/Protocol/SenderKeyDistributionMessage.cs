

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
using libsignal.util;
using System;

namespace libsignal.protocol
{
    public partial class SenderKeyDistributionMessage : CiphertextMessage
    {

        private readonly uint _id;
        private readonly uint _iteration;
        private readonly byte[] _chainKey;
        private readonly IEcPublicKey _signatureKey;
        private readonly byte[] _serialized;

        public SenderKeyDistributionMessage(uint id, uint iteration, byte[] chainKey, IEcPublicKey signatureKey)
        {
            byte[] version = { ByteUtil.IntsToByteHighAndLow((int)CurrentVersion, (int)CurrentVersion) };
            byte[] protobuf = new SenderKeyDistributionMessage
            {
                Id = id,
                Iteration = iteration,
                ChainKey = ByteString.CopyFrom(chainKey),
                SigningKey = ByteString.CopyFrom(signatureKey.Serialize())

            }.ToByteArray();

            this._id = id;
            this._iteration = iteration;
            this._chainKey = chainKey;
            this._signatureKey = signatureKey;
            this._serialized = ByteUtil.Combine(version, protobuf);
        }

        public SenderKeyDistributionMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.Split(serialized, 1, serialized.Length - 1);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];

                if (ByteUtil.HighBitsToInt(version) < CiphertextMessage.CurrentVersion)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.HighBitsToInt(version));
                }

                if (ByteUtil.HighBitsToInt(version) > CurrentVersion)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.HighBitsToInt(version));
                }

                SenderKeyDistributionMessage distributionMessage = SenderKeyDistributionMessage.Parser.ParseFrom(message);

                if (distributionMessage.IdOneofCase == IdOneofOneofCase.None ||
                    distributionMessage.IterationOneofCase == IterationOneofOneofCase.None ||
                    distributionMessage.ChainKeyOneofCase == ChainKeyOneofOneofCase.None ||
                    distributionMessage.SigningKeyOneofCase == SigningKeyOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this._serialized = serialized;
                this._id = distributionMessage.Id;
                this._iteration = distributionMessage.Iteration;
                this._chainKey = distributionMessage.ChainKey.ToByteArray();
                this._signatureKey = Curve.DecodePoint(distributionMessage.SigningKey.ToByteArray(), 0);
            }
            catch (Exception e)
            {
                //InvalidProtocolBufferException | InvalidKey
                throw new InvalidMessageException(e);
            }
        }

        public override byte[] Serialize()
        {
            return _serialized;
        }


        public override uint GetMessageType()
        {
            return SenderkeyDistributionType;
        }

        public uint GetIteration()
        {
            return _iteration;
        }

        public byte[] GetChainKey()
        {
            return _chainKey;
        }

        public IEcPublicKey GetSignatureKey()
        {
            return _signatureKey;
        }

        public uint GetId()
        {
            return _id;
        }
    }
}
