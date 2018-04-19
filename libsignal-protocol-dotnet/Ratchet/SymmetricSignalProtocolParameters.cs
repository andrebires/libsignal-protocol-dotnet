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

namespace Libsignal.Ratchet
{
    public class SymmetricSignalProtocolParameters
    {

        private readonly EcKeyPair       _ourBaseKey;
  private readonly EcKeyPair       _ourRatchetKey;
  private readonly IdentityKeyPair _ourIdentityKey;

  private readonly IEcPublicKey     _theirBaseKey;
  private readonly IEcPublicKey     _theirRatchetKey;
  private readonly IdentityKey     _theirIdentityKey;

  SymmetricSignalProtocolParameters(EcKeyPair ourBaseKey, EcKeyPair ourRatchetKey,
                             IdentityKeyPair ourIdentityKey, IEcPublicKey theirBaseKey,
                             IEcPublicKey theirRatchetKey, IdentityKey theirIdentityKey)
        {
            _ourBaseKey = ourBaseKey;
            _ourRatchetKey = ourRatchetKey;
            _ourIdentityKey = ourIdentityKey;
            _theirBaseKey = theirBaseKey;
            _theirRatchetKey = theirRatchetKey;
            _theirIdentityKey = theirIdentityKey;

            if (ourBaseKey == null || ourRatchetKey == null || ourIdentityKey == null ||
                theirBaseKey == null || theirRatchetKey == null || theirIdentityKey == null)
            {
                throw new Exception("Null values!");
            }
        }

        public EcKeyPair GetOurBaseKey()
        {
            return _ourBaseKey;
        }

        public EcKeyPair GetOurRatchetKey()
        {
            return _ourRatchetKey;
        }

        public IdentityKeyPair GetOurIdentityKey()
        {
            return _ourIdentityKey;
        }

        public IEcPublicKey GetTheirBaseKey()
        {
            return _theirBaseKey;
        }

        public IEcPublicKey GetTheirRatchetKey()
        {
            return _theirRatchetKey;
        }

        public IdentityKey GetTheirIdentityKey()
        {
            return _theirIdentityKey;
        }

        public static Builder NewBuilder()
        {
            return new Builder();
        }

        public class Builder
        {
            private EcKeyPair _ourBaseKey;
            private EcKeyPair _ourRatchetKey;
            private IdentityKeyPair _ourIdentityKey;

            private IEcPublicKey _theirBaseKey;
            private IEcPublicKey _theirRatchetKey;
            private IdentityKey _theirIdentityKey;

            public Builder SetOurBaseKey(EcKeyPair ourBaseKey)
            {
                _ourBaseKey = ourBaseKey;
                return this;
            }

            public Builder SetOurRatchetKey(EcKeyPair ourRatchetKey)
            {
                _ourRatchetKey = ourRatchetKey;
                return this;
            }

            public Builder SetOurIdentityKey(IdentityKeyPair ourIdentityKey)
            {
                _ourIdentityKey = ourIdentityKey;
                return this;
            }

            public Builder SetTheirBaseKey(IEcPublicKey theirBaseKey)
            {
                _theirBaseKey = theirBaseKey;
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

            public SymmetricSignalProtocolParameters Create()
            {
                return new SymmetricSignalProtocolParameters(_ourBaseKey, _ourRatchetKey, _ourIdentityKey,
                                                      _theirBaseKey, _theirRatchetKey, _theirIdentityKey);
            }
        }
    }
}
