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
using System.Collections.Generic;

namespace Libsignal.State.Impl
{
    public class InMemorySignalProtocolStore : ISignalProtocolStore
    {

        private readonly InMemoryPreKeyStore _preKeyStore = new InMemoryPreKeyStore();
        private readonly InMemorySessionStore _sessionStore = new InMemorySessionStore();
        private readonly InMemorySignedPreKeyStore _signedPreKeyStore = new InMemorySignedPreKeyStore();

        private readonly InMemoryIdentityKeyStore _identityKeyStore;

        public InMemorySignalProtocolStore(IdentityKeyPair identityKeyPair, uint registrationId)
        {
            this._identityKeyStore = new InMemoryIdentityKeyStore(identityKeyPair, registrationId);
        }


        public IdentityKeyPair GetIdentityKeyPair()
        {
            return _identityKeyStore.GetIdentityKeyPair();
        }


        public uint GetLocalRegistrationId()
        {
            return _identityKeyStore.GetLocalRegistrationId();
        }


        public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            return _identityKeyStore.SaveIdentity(address, identityKey);
        }


        public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction)
        {
            return _identityKeyStore.IsTrustedIdentity(address, identityKey, direction);
        }


        public PreKeyRecord LoadPreKey(uint preKeyId)
        {
            return _preKeyStore.LoadPreKey(preKeyId);
        }


        public void StorePreKey(uint preKeyId, PreKeyRecord record)
        {
            _preKeyStore.StorePreKey(preKeyId, record);
        }


        public bool ContainsPreKey(uint preKeyId)
        {
            return _preKeyStore.ContainsPreKey(preKeyId);
        }


        public void RemovePreKey(uint preKeyId)
        {
            _preKeyStore.RemovePreKey(preKeyId);
        }


        public SessionRecord LoadSession(SignalProtocolAddress address)
        {
            return _sessionStore.LoadSession(address);
        }


        public List<uint> GetSubDeviceSessions(String name)
        {
            return _sessionStore.GetSubDeviceSessions(name);
        }


        public void StoreSession(SignalProtocolAddress address, SessionRecord record)
        {
            _sessionStore.StoreSession(address, record);
        }


        public bool ContainsSession(SignalProtocolAddress address)
        {
            return _sessionStore.ContainsSession(address);
        }


        public void DeleteSession(SignalProtocolAddress address)
        {
            _sessionStore.DeleteSession(address);
        }


        public void DeleteAllSessions(String name)
        {
            _sessionStore.DeleteAllSessions(name);
        }


        public SignedPreKeyRecord LoadSignedPreKey(uint signedPreKeyId)
        {
            return _signedPreKeyStore.LoadSignedPreKey(signedPreKeyId);
        }


        public List<SignedPreKeyRecord> LoadSignedPreKeys()
        {
            return _signedPreKeyStore.LoadSignedPreKeys();
        }


        public void StoreSignedPreKey(uint signedPreKeyId, SignedPreKeyRecord record)
        {
            _signedPreKeyStore.StoreSignedPreKey(signedPreKeyId, record);
        }


        public bool ContainsSignedPreKey(uint signedPreKeyId)
        {
            return _signedPreKeyStore.ContainsSignedPreKey(signedPreKeyId);
        }


        public void RemoveSignedPreKey(uint signedPreKeyId)
        {
            _signedPreKeyStore.RemoveSignedPreKey(signedPreKeyId);
        }
    }
}
