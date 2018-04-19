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

using System.Collections.Generic;

namespace Libsignal.State.Impl
{
    /// <summary>
    /// In-memory / testing implementation of IdentityKeyStore
    /// </summary>
    public class InMemoryIdentityKeyStore : IDentityKeyStore
    {

        private readonly IDictionary<SignalProtocolAddress, IdentityKey> _trustedKeys = new Dictionary<SignalProtocolAddress, IdentityKey>();

        private readonly IdentityKeyPair _identityKeyPair;
        private readonly uint _localRegistrationId;

        /// <summary>
        /// .ctor
        /// </summary>
        public InMemoryIdentityKeyStore(IdentityKeyPair identityKeyPair, uint localRegistrationId)
        {
            this._identityKeyPair = identityKeyPair;
            this._localRegistrationId = localRegistrationId;
        }

        public IdentityKeyPair GetIdentityKeyPair()
        {
            return _identityKeyPair;
        }


        public uint GetLocalRegistrationId()
        {
            return _localRegistrationId;
        }

        public bool SaveIdentity(SignalProtocolAddress address, IdentityKey identityKey)
        {
            IdentityKey existing;
            _trustedKeys.TryGetValue(address, out existing);

            if (!identityKey.Equals(existing))
            {
                _trustedKeys[address] = identityKey;
                return true;
            }
            else
            {
                return false;
            }
        }

        public bool IsTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey, Direction direction)
        {
            IdentityKey trusted;
            _trustedKeys.TryGetValue(address, out trusted); // get(name)
            return (trusted == null || trusted.Equals(identityKey));
        }
    }
}
