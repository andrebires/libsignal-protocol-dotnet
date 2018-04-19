using System;
using System.IO;
using System.Linq;
using Google.Protobuf;
using Libsignal.Ecc;
using Libsignal.Util;
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

namespace Libsignal.Protocol
{
    public partial class SignalMessage : CiphertextMessage
    {

        private static readonly int MacLength = 8;

        private readonly uint _messageVersion;
        private readonly IEcPublicKey _senderRatchetKey;
        private readonly uint _counter;
        private readonly uint _previousCounter;
        private readonly byte[] _ciphertext;
        private readonly byte[] _serialized;

        public SignalMessage(byte[] serialized)
        {
            try
            {
                byte[][] messageParts = ByteUtil.Split(serialized, 1, serialized.Length - 1 - MacLength, MacLength);
                byte version = messageParts[0][0];
                byte[] message = messageParts[1];
                byte[] mac = messageParts[2];

                if (ByteUtil.HighBitsToInt(version) < CurrentVersion)
                {
                    throw new LegacyMessageException("Legacy message: " + ByteUtil.HighBitsToInt(version));
                }

                if (ByteUtil.HighBitsToInt(version) > CurrentVersion)
                {
                    throw new InvalidMessageException("Unknown version: " + ByteUtil.HighBitsToInt(version));
                }

                SignalMessage signalMessage = SignalMessage.Parser.ParseFrom(message);






                if (signalMessage.CiphertextOneofCase == CiphertextOneofOneofCase.None ||
                    signalMessage.CounterOneofCase == CounterOneofOneofCase.None ||
                    signalMessage.RatchedKeyOneofCase == RatchedKeyOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                this._serialized = serialized;
                this._senderRatchetKey = Curve.DecodePoint(signalMessage.RatchetKey.ToByteArray(), 0);
                this._messageVersion = (uint)ByteUtil.HighBitsToInt(version);
                this._counter = signalMessage.Counter;
                this._previousCounter = signalMessage.PreviousCounter;
                this._ciphertext = signalMessage.Ciphertext.ToByteArray();
            }
            catch (/*InvalidProtocolBufferException | InvalidKeyException | Parse*/Exception e)
            {
                throw new InvalidMessageException(e);
            }
        }

        public SignalMessage(uint messageVersion, byte[] macKey, IEcPublicKey senderRatchetKey,
                              uint counter, uint previousCounter, byte[] ciphertext,
                              IdentityKey senderIdentityKey,
                              IdentityKey receiverIdentityKey)
        {
            byte[] version = { ByteUtil.IntsToByteHighAndLow((int)messageVersion, (int)CurrentVersion) };
            byte[] message = new SignalMessage
            {
                ratchedKeyOneofCase_ = RatchedKeyOneofOneofCase.RatchetKey,
                RatchetKey = ByteString.CopyFrom(senderRatchetKey.Serialize()), //TODO serialize ok?
                counterOneofCase_ = CounterOneofOneofCase.Counter,
                Counter = counter,
                previousCounterOneofCase_ = PreviousCounterOneofOneofCase.PreviousCounter,
                PreviousCounter = previousCounter,
                ciphertextOneofCase_ = CiphertextOneofOneofCase.Ciphertext,
                Ciphertext = ByteString.CopyFrom(ciphertext),
            }.ToByteArray();

            byte[] mac = GetMac(senderIdentityKey, receiverIdentityKey, macKey, ByteUtil.Combine(version, message));

            this._serialized = ByteUtil.Combine(version, message, mac);
            this._senderRatchetKey = senderRatchetKey;
            this._counter = counter;
            this._previousCounter = previousCounter;
            this._ciphertext = ciphertext;
            this._messageVersion = messageVersion;
        }

        public IEcPublicKey GetSenderRatchetKey()
        {
            return _senderRatchetKey;
        }

        public uint GetMessageVersion()
        {
            return _messageVersion;
        }

        public uint GetCounter()
        {
            return _counter;
        }

        public byte[] GetBody()
        {
            return _ciphertext;
        }

        public void VerifyMac(IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey, byte[] macKey)
        {
            byte[][] parts = ByteUtil.Split(_serialized, _serialized.Length - MacLength, MacLength);
            byte[] ourMac = GetMac(senderIdentityKey, receiverIdentityKey, macKey, parts[0]);
            byte[] theirMac = parts[1];

            if (!Enumerable.SequenceEqual(ourMac, theirMac))
            {
                throw new InvalidMessageException("Bad Mac!");
            }
        }

        private byte[] GetMac(IdentityKey senderIdentityKey,
                        IdentityKey receiverIdentityKey,
                        byte[] macKey, byte[] serialized)
        {
            try
            {
                MemoryStream stream = new MemoryStream();
                byte[] sik = senderIdentityKey.GetPublicKey().Serialize();
                stream.Write(sik, 0, sik.Length);
                byte[] rik = receiverIdentityKey.GetPublicKey().Serialize();
                stream.Write(rik, 0, rik.Length);

                stream.Write(serialized, 0, serialized.Length);
                byte[] fullMac = Sign.Sha256Sum(macKey, stream.ToArray());
                return ByteUtil.Trim(fullMac, MacLength);
            }
            catch (/*NoSuchAlgorithmException | java.security.InvalidKey*/Exception e)
            {
                throw new Exception(e.Message);
            }
        }

        public override byte[] Serialize()
        {
            return _serialized;
        }

        public override uint GetMessageType()
        {
            return CiphertextMessage.WhisperType;
        }

        public static bool IsLegacy(byte[] message)
        {
            return message != null && message.Length >= 1 &&
                ByteUtil.HighBitsToInt(message[0]) != CurrentVersion;
        }

    }
}
