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
    public class BobSignalProtocolParameters
    {

        private readonly IdentityKeyPair _ourIdentityKey;
        private readonly EcKeyPair _ourSignedPreKey;
        private readonly May<EcKeyPair> _ourOneTimePreKey;
        private readonly EcKeyPair _ourRatchetKey;

        private readonly IdentityKey _theirIdentityKey;
        private readonly IEcPublicKey _theirBaseKey;

        BobSignalProtocolParameters(IdentityKeyPair ourIdentityKey, EcKeyPair ourSignedPreKey,
                             EcKeyPair ourRatchetKey, May<EcKeyPair> ourOneTimePreKey,
                             IdentityKey theirIdentityKey, IEcPublicKey theirBaseKey)
        {
            _ourIdentityKey = ourIdentityKey;
            _ourSignedPreKey = ourSignedPreKey;
            _ourRatchetKey = ourRatchetKey;
            _ourOneTimePreKey = ourOneTimePreKey;
            _theirIdentityKey = theirIdentityKey;
            _theirBaseKey = theirBaseKey;

            if (ourIdentityKey == null || ourSignedPreKey == null || ourRatchetKey == null ||
                ourOneTimePreKey == null || theirIdentityKey == null || theirBaseKey == null)
            {
                throw new Exception("Null value!");
            }
        }

        public IdentityKeyPair GetOurIdentityKey()
        {
            return _ourIdentityKey;
        }

        public EcKeyPair GetOurSignedPreKey()
        {
            return _ourSignedPreKey;
        }

        public May<EcKeyPair> GetOurOneTimePreKey()
        {
            return _ourOneTimePreKey;
        }

        public IdentityKey GetTheirIdentityKey()
        {
            return _theirIdentityKey;
        }

        public IEcPublicKey GetTheirBaseKey()
        {
            return _theirBaseKey;
        }

        public static Builder NewBuilder()
        {
            return new Builder();
        }

        public EcKeyPair GetOurRatchetKey()
        {
            return _ourRatchetKey;
        }

        public class Builder
        {
            private IdentityKeyPair _ourIdentityKey;
            private EcKeyPair _ourSignedPreKey;
            private May<EcKeyPair> _ourOneTimePreKey;
            private EcKeyPair _ourRatchetKey;

            private IdentityKey _theirIdentityKey;
            private IEcPublicKey _theirBaseKey;

            public Builder SetOurIdentityKey(IdentityKeyPair ourIdentityKey)
            {
                _ourIdentityKey = ourIdentityKey;
                return this;
            }

            public Builder SetOurSignedPreKey(EcKeyPair ourSignedPreKey)
            {
                _ourSignedPreKey = ourSignedPreKey;
                return this;
            }

            public Builder SetOurOneTimePreKey(May<EcKeyPair> ourOneTimePreKey)
            {
                _ourOneTimePreKey = ourOneTimePreKey;
                return this;
            }

            public Builder SetTheirIdentityKey(IdentityKey theirIdentityKey)
            {
                _theirIdentityKey = theirIdentityKey;
                return this;
            }

            public Builder SetTheirBaseKey(IEcPublicKey theirBaseKey)
            {
                _theirBaseKey = theirBaseKey;
                return this;
            }

            public Builder SetOurRatchetKey(EcKeyPair ourRatchetKey)
            {
                _ourRatchetKey = ourRatchetKey;
                return this;
            }

            public BobSignalProtocolParameters Create()
            {
                return new BobSignalProtocolParameters(_ourIdentityKey, _ourSignedPreKey, _ourRatchetKey,
                                                _ourOneTimePreKey, _theirIdentityKey, _theirBaseKey);
            }
        }
    }
}
