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
using libsignal.kdf;
using libsignal.protocol;
using libsignal.state;
using libsignal.util;
using Strilanc.Value;
using System;
using System.IO;
using System.Text;

namespace libsignal.ratchet
{
    public class RatchetingSession
    {

        public static void InitializeSession(SessionState sessionState,
                                             SymmetricSignalProtocolParameters parameters)
        {
            if (IsAlice(parameters.GetOurBaseKey().GetPublicKey(), parameters.GetTheirBaseKey()))
            {
                AliceSignalProtocolParameters.Builder aliceParameters = AliceSignalProtocolParameters.NewBuilder();

                aliceParameters.SetOurBaseKey(parameters.GetOurBaseKey())
                               .SetOurIdentityKey(parameters.GetOurIdentityKey())
                               .SetTheirRatchetKey(parameters.GetTheirRatchetKey())
                               .SetTheirIdentityKey(parameters.GetTheirIdentityKey())
                               .SetTheirSignedPreKey(parameters.GetTheirBaseKey())
                               .SetTheirOneTimePreKey(May<IEcPublicKey>.NoValue);

                RatchetingSession.InitializeSession(sessionState, aliceParameters.Create());
            }
            else
            {
                BobSignalProtocolParameters.Builder bobParameters = BobSignalProtocolParameters.NewBuilder();

                bobParameters.SetOurIdentityKey(parameters.GetOurIdentityKey())
                             .SetOurRatchetKey(parameters.GetOurRatchetKey())
                             .SetOurSignedPreKey(parameters.GetOurBaseKey())
                             .SetOurOneTimePreKey(May<EcKeyPair>.NoValue)
                             .SetTheirBaseKey(parameters.GetTheirBaseKey())
                             .SetTheirIdentityKey(parameters.GetTheirIdentityKey());

                RatchetingSession.InitializeSession(sessionState, bobParameters.Create());
            }
        }

        public static void InitializeSession(SessionState sessionState, AliceSignalProtocolParameters parameters)

        {
            try
            {
                sessionState.SetSessionVersion(CiphertextMessage.CurrentVersion);
                sessionState.SetRemoteIdentityKey(parameters.GetTheirIdentityKey());
                sessionState.SetLocalIdentityKey(parameters.GetOurIdentityKey().GetPublicKey());

                EcKeyPair sendingRatchetKey = Curve.GenerateKeyPair();
                MemoryStream secrets = new MemoryStream();

                byte[] discontinuityBytes = GetDiscontinuityBytes();
                secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);

                byte[] agree1 = Curve.CalculateAgreement(parameters.GetTheirSignedPreKey(),
                                                       parameters.GetOurIdentityKey().GetPrivateKey());
                byte[] agree2 = Curve.CalculateAgreement(parameters.GetTheirIdentityKey().GetPublicKey(),
                                                        parameters.GetOurBaseKey().GetPrivateKey());
                byte[] agree3 = Curve.CalculateAgreement(parameters.GetTheirSignedPreKey(),
                                                       parameters.GetOurBaseKey().GetPrivateKey());

                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);


                if (parameters.GetTheirOneTimePreKey().HasValue)
                {
                    byte[] otAgree = Curve.CalculateAgreement(parameters.GetTheirOneTimePreKey().ForceGetValue(),
                                                           parameters.GetOurBaseKey().GetPrivateKey());
                    secrets.Write(otAgree, 0, otAgree.Length);
                }

                DerivedKeys derivedKeys = CalculateDerivedKeys(secrets.ToArray());
                Pair<RootKey, ChainKey> sendingChain = derivedKeys.GetRootKey().CreateChain(parameters.GetTheirRatchetKey(), sendingRatchetKey);

                sessionState.AddReceiverChain(parameters.GetTheirRatchetKey(), derivedKeys.GetChainKey());
                sessionState.SetSenderChain(sendingRatchetKey, sendingChain.Second());
                sessionState.SetRootKey(sendingChain.First());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        public static void InitializeSession(SessionState sessionState,
                                             BobSignalProtocolParameters parameters)
        {

            try
            {
                sessionState.SetSessionVersion(CiphertextMessage.CurrentVersion);
                sessionState.SetRemoteIdentityKey(parameters.GetTheirIdentityKey());
                sessionState.SetLocalIdentityKey(parameters.GetOurIdentityKey().GetPublicKey());

                MemoryStream secrets = new MemoryStream();

                byte[] discontinuityBytes = GetDiscontinuityBytes();
                secrets.Write(discontinuityBytes, 0, discontinuityBytes.Length);

                byte[] agree1 = Curve.CalculateAgreement(parameters.GetTheirIdentityKey().GetPublicKey(),
                                                       parameters.GetOurSignedPreKey().GetPrivateKey());
                byte[] agree2 = Curve.CalculateAgreement(parameters.GetTheirBaseKey(),
                                                       parameters.GetOurIdentityKey().GetPrivateKey());
                byte[] agree3 = Curve.CalculateAgreement(parameters.GetTheirBaseKey(),
                                                       parameters.GetOurSignedPreKey().GetPrivateKey());
                secrets.Write(agree1, 0, agree1.Length);
                secrets.Write(agree2, 0, agree2.Length);
                secrets.Write(agree3, 0, agree3.Length);

                if (parameters.GetOurOneTimePreKey().HasValue)
                {
                    byte[] otAgree = Curve.CalculateAgreement(parameters.GetTheirBaseKey(),
                                                           parameters.GetOurOneTimePreKey().ForceGetValue().GetPrivateKey());
                    secrets.Write(otAgree, 0, otAgree.Length);
                }

                DerivedKeys derivedKeys = CalculateDerivedKeys(secrets.ToArray());

                sessionState.SetSenderChain(parameters.GetOurRatchetKey(), derivedKeys.GetChainKey());
                sessionState.SetRootKey(derivedKeys.GetRootKey());
            }
            catch (IOException e)
            {
                throw new Exception(e.Message);
            }
        }

        private static byte[] GetDiscontinuityBytes()
        {
            byte[] discontinuity = new byte[32];
            //Arrays.fill(discontinuity, (byte)0xFF);
            for (int i = 0; i < discontinuity.Length; i++)
            {
                discontinuity[i] = 0xFF;
            }
            return discontinuity;
        }

        private static DerivedKeys CalculateDerivedKeys(byte[] masterSecret)
        {
            Hkdf kdf = new HkdFv3();
            byte[] derivedSecretBytes = kdf.DeriveSecrets(masterSecret, Encoding.UTF8.GetBytes("WhisperText"), 64);
            byte[][] derivedSecrets = ByteUtil.Split(derivedSecretBytes, 32, 32);

            return new DerivedKeys(new RootKey(kdf, derivedSecrets[0]),
                                   new ChainKey(kdf, derivedSecrets[1], 0));
        }

        private static bool IsAlice(IEcPublicKey ourKey, IEcPublicKey theirKey)
        {
            return ourKey.CompareTo(theirKey) < 0;
        }

        public class DerivedKeys
        {
            private readonly RootKey _rootKey;
            private readonly ChainKey _chainKey;

            internal DerivedKeys(RootKey rootKey, ChainKey chainKey)
            {
                this._rootKey = rootKey;
                this._chainKey = chainKey;
            }

            public RootKey GetRootKey()
            {
                return _rootKey;
            }

            public ChainKey GetChainKey()
            {
                return _chainKey;
            }
        }
    }
}
