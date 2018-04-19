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
using Strilanc.Value;

namespace Libsignal.Ratchet
{
    public class AliceSignalProtocolParameters
    {

        private readonly IdentityKeyPair _ourIdentityKey;
        private readonly EcKeyPair _ourBaseKey;

        private readonly IdentityKey _theirIdentityKey;
        private readonly IEcPublicKey _theirSignedPreKey;
        private readonly May<IEcPublicKey> _theirOneTimePreKey;
        private readonly IEcPublicKey _theirRatchetKey;

        private AliceSignalProtocolParameters(IdentityKeyPair ourIdentityKey, EcKeyPair ourBaseKey,
                                       IdentityKey theirIdentityKey, IEcPublicKey theirSignedPreKey,
                                       IEcPublicKey theirRatchetKey, May<IEcPublicKey> theirOneTimePreKey)
        {
            _ourIdentityKey = ourIdentityKey;
            _ourBaseKey = ourBaseKey;
            _theirIdentityKey = theirIdentityKey;
            _theirSignedPreKey = theirSignedPreKey;
            _theirRatchetKey = theirRatchetKey;
            _theirOneTimePreKey = theirOneTimePreKey;

            if (ourIdentityKey == null || ourBaseKey == null || theirIdentityKey == null ||
                theirSignedPreKey == null || theirRatchetKey == null || theirOneTimePreKey == null)
            {
                throw new Exception("Null values!");
            }
        }

        public IdentityKeyPair GetOurIdentityKey()
        {
            return _ourIdentityKey;
        }

        public EcKeyPair GetOurBaseKey()
        {
            return _ourBaseKey;
        }

        public IdentityKey GetTheirIdentityKey()
        {
            return _theirIdentityKey;
        }

        public IEcPublicKey GetTheirSignedPreKey()
        {
            return _theirSignedPreKey;
        }

        public May<IEcPublicKey> GetTheirOneTimePreKey()
        {
            return _theirOneTimePreKey;
        }

        public static Builder NewBuilder()
        {
            return new Builder();
        }

        public IEcPublicKey GetTheirRatchetKey()
        {
            return _theirRatchetKey;
        }

        public class Builder
        {
            private IdentityKeyPair _ourIdentityKey;
            private EcKeyPair _ourBaseKey;

            private IdentityKey _theirIdentityKey;
            private IEcPublicKey _theirSignedPreKey;
            private IEcPublicKey _theirRatchetKey;
            private May<IEcPublicKey> _theirOneTimePreKey;

            public Builder SetOurIdentityKey(IdentityKeyPair ourIdentityKey)
            {
                _ourIdentityKey = ourIdentityKey;
                return this;
            }

            public Builder SetOurBaseKey(EcKeyPair ourBaseKey)
            {
                _ourBaseKey = ourBaseKey;
                return this;
            }

            public Builder SetTheirRatchetKey(IEcPublicKey theirRatchetKey)
            {
                _theirRatchetKey = theirRatchetKey;
                return this;
            }

            public Builder SetTheirIdentityKey(IdentityKey theirIdentityKey)
            {
                _theirIdentityKey = theirIdentityKey;
                return this;
            }

            public Builder SetTheirSignedPreKey(IEcPublicKey theirSignedPreKey)
            {
                _theirSignedPreKey = theirSignedPreKey;
                return this;
            }

            public Builder SetTheirOneTimePreKey(May<IEcPublicKey> theirOneTimePreKey)
            {
                _theirOneTimePreKey = theirOneTimePreKey;
                return this;
            }

            public AliceSignalProtocolParameters Create()
            {
                return new AliceSignalProtocolParameters(_ourIdentityKey, _ourBaseKey, _theirIdentityKey,
                                                  _theirSignedPreKey, _theirRatchetKey, _theirOneTimePreKey);
            }
        }
    }
}
