﻿using System;
using Google.Protobuf;
using Libsignal.Ecc;
using Libsignal.Util;
using Strilanc.Value;
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
    public partial class PreKeySignalMessage : CiphertextMessage
    {

        private readonly uint _version;
        private readonly uint _registrationId;
        private readonly May<uint> _preKeyId;
        private readonly uint _signedPreKeyId;
        private readonly IEcPublicKey _baseKey;
        private readonly IdentityKey _identityKey;
        private readonly SignalMessage _message;
        private readonly byte[] _serialized;

        public PreKeySignalMessage(byte[] serialized)
        {
            try
            {
                _version = (uint)ByteUtil.HighBitsToInt(serialized[0]);

                if (_version > CurrentVersion)
                {
                    throw new InvalidVersionException("Unknown version: " + _version);
                }

                if (_version < CurrentVersion) {
                throw new LegacyMessageException("Legacy version: " + _version);
                }
                PreKeySignalMessage preKeySignalMessage = Parser.ParseFrom(ByteString.CopyFrom(serialized, 1, serialized.Length - 1));

                if (
                    preKeySignalMessage.SignedPreKeyIdOneofCase == SignedPreKeyIdOneofOneofCase.None ||
                    preKeySignalMessage.BaseKeyOneofCase == BaseKeyOneofOneofCase.None ||
                    preKeySignalMessage.BaseKeyOneofCase == BaseKeyOneofOneofCase.None ||
                    preKeySignalMessage.MessageOneofCase == MessageOneofOneofCase.None)
                {
                    throw new InvalidMessageException("Incomplete message.");
                }

                _serialized = serialized;
                _registrationId = preKeySignalMessage.RegistrationId;
                _preKeyId = preKeySignalMessage.PreKeyIdOneofCase == PreKeyIdOneofOneofCase.PreKeyId ? new May<uint>(preKeySignalMessage.PreKeyId) : May<uint>.NoValue;
                _signedPreKeyId = preKeySignalMessage.SignedPreKeyIdOneofCase == SignedPreKeyIdOneofOneofCase.SignedPreKeyId ? preKeySignalMessage.SignedPreKeyId : uint.MaxValue; // -1
                _baseKey = Curve.DecodePoint(preKeySignalMessage.BaseKey.ToByteArray(), 0);
                _identityKey = new IdentityKey(Curve.DecodePoint(preKeySignalMessage.IdentityKey.ToByteArray(), 0));
                _message = new SignalMessage(preKeySignalMessage.Message.ToByteArray());
            }
            catch (Exception e)
            {
                //(InvalidProtocolBufferException | InvalidKeyException | LegacyMessage
                throw new InvalidMessageException(e.Message);
            }
        }

        public PreKeySignalMessage(uint messageVersion, uint registrationId, May<uint> preKeyId,
                                    uint signedPreKeyId, IEcPublicKey baseKey, IdentityKey identityKey,
                                    SignalMessage message)
        {
            _version = messageVersion;
            _registrationId = registrationId;
            _preKeyId = preKeyId;
            _signedPreKeyId = signedPreKeyId;
            _baseKey = baseKey;
            _identityKey = identityKey;
            _message = message;

            PreKeySignalMessage preKeySignalMessage = new PreKeySignalMessage
            {
                SignedPreKeyId = signedPreKeyId,
                BaseKey = ByteString.CopyFrom(baseKey.Serialize()),
                IdentityKey = ByteString.CopyFrom(identityKey.Serialize()),
                Message = ByteString.CopyFrom(message.Serialize()),
                RegistrationId = registrationId
            };

            if (preKeyId.HasValue) // .isPresent()
            {
                preKeySignalMessage.PreKeyId = preKeyId.ForceGetValue(); // get()
            }

            byte[] versionBytes = { ByteUtil.IntsToByteHighAndLow((int)_version, (int)CurrentVersion) };
            byte[] messageBytes = preKeySignalMessage.ToByteArray();

            _serialized = ByteUtil.Combine(versionBytes, messageBytes);
        }

        public uint GetMessageVersion()
        {
            return _version;
        }

        public IdentityKey GetIdentityKey()
        {
            return _identityKey;
        }

        public uint GetRegistrationId()
        {
            return _registrationId;
        }

        public May<uint> GetPreKeyId()
        {
            return _preKeyId;
        }

        public uint GetSignedPreKeyId()
        {
            return _signedPreKeyId;
        }

        public IEcPublicKey GetBaseKey()
        {
            return _baseKey;
        }

        public SignalMessage GetSignalMessage()
        {
            return _message;
        }


        public override byte[] Serialize()
        {
            return _serialized;
        }


        public override uint GetMessageType()
        {
            return PrekeyType;
        }

    }
}
