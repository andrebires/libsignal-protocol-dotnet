/** 
 * Copyright (C) 2016 langboost
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

using libsignal;
using libsignal.ecc;
using libsignal.protocol;
using libsignal.ratchet;
using libsignal.state;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Strilanc.Value;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using signal_protocol_tests;

namespace libsignal_test
{
    [TestClass]
    public class SessionCipherTest
    {
        [TestMethod, TestCategory("libsignal")]
        public void TestBasicSessionV3()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            InitializeSessionsV3(aliceSessionRecord.GetSessionState(), bobSessionRecord.GetSessionState());
            RunInteraction(aliceSessionRecord, bobSessionRecord);
        }

        [TestMethod, TestCategory("libsignal")]
        public void TestMessageKeyLimits()
        {
            SessionRecord aliceSessionRecord = new SessionRecord();
            SessionRecord bobSessionRecord = new SessionRecord();

            InitializeSessionsV3(aliceSessionRecord.GetSessionState(), bobSessionRecord.GetSessionState());

            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            List<CiphertextMessage> inflight = new List<CiphertextMessage>();

            for (int i = 0; i < 2010; i++)
            {
                inflight.Add(aliceCipher.Encrypt(Encoding.UTF8.GetBytes("you've never been so hungry, you've never been so cold")));
            }

            bobCipher.Decrypt(new SignalMessage(inflight[1000].Serialize()));
            bobCipher.Decrypt(new SignalMessage(inflight[inflight.Count - 1].Serialize()));

            try
            {
                bobCipher.Decrypt(new SignalMessage(inflight[0].Serialize()));
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException)
            {
                // good
            }
        }

        private void RunInteraction(SessionRecord aliceSessionRecord, SessionRecord bobSessionRecord)
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            aliceStore.StoreSession(new SignalProtocolAddress("+14159999999", 1), aliceSessionRecord);
            bobStore.StoreSession(new SignalProtocolAddress("+14158888888", 1), bobSessionRecord);

            SessionCipher aliceCipher = new SessionCipher(aliceStore, new SignalProtocolAddress("+14159999999", 1));
            SessionCipher bobCipher = new SessionCipher(bobStore, new SignalProtocolAddress("+14158888888", 1));

            byte[] alicePlaintext = Encoding.UTF8.GetBytes("This is a plaintext message.");
            CiphertextMessage message = aliceCipher.Encrypt(alicePlaintext);
            byte[] bobPlaintext = bobCipher.Decrypt(new SignalMessage(message.Serialize()));

            CollectionAssert.AreEqual(alicePlaintext, bobPlaintext);

            byte[] bobReply = Encoding.UTF8.GetBytes("This is a message from Bob.");
            CiphertextMessage reply = bobCipher.Encrypt(bobReply);
            byte[] receivedReply = aliceCipher.Decrypt(new SignalMessage(reply.Serialize()));

            CollectionAssert.AreEqual(bobReply, receivedReply);

            List<CiphertextMessage> aliceCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> alicePlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 50; i++)
            {
                alicePlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                aliceCiphertextMessages.Add(aliceCipher.Encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            ulong seed = DateUtil.CurrentTimeMillis();

            HelperMethods.Shuffle(aliceCiphertextMessages, new Random((int)seed));
            HelperMethods.Shuffle(alicePlaintextMessages, new Random((int)seed));

            for (int i = 0; i < aliceCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = bobCipher.Decrypt(new SignalMessage(aliceCiphertextMessages[i].Serialize()));
                Assert.IsTrue(libsignal.util.ByteUtil.IsEqual(receivedPlaintext, alicePlaintextMessages[i]));
            }

            List<CiphertextMessage> bobCiphertextMessages = new List<CiphertextMessage>();
            List<byte[]> bobPlaintextMessages = new List<byte[]>();

            for (int i = 0; i < 20; i++)
            {
                bobPlaintextMessages.Add(Encoding.UTF8.GetBytes("смерть за смерть " + i));
                bobCiphertextMessages.Add(bobCipher.Encrypt(Encoding.UTF8.GetBytes("смерть за смерть " + i)));
            }

            seed = DateUtil.CurrentTimeMillis();

            HelperMethods.Shuffle(bobCiphertextMessages, new Random((int)seed));
            HelperMethods.Shuffle(bobPlaintextMessages, new Random((int)seed));

            for (int i = 0; i < bobCiphertextMessages.Count / 2; i++)
            {
                byte[] receivedPlaintext = aliceCipher.Decrypt(new SignalMessage(bobCiphertextMessages[i].Serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }

            for (int i = aliceCiphertextMessages.Count / 2; i < aliceCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = bobCipher.Decrypt(new SignalMessage(aliceCiphertextMessages[i].Serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, alicePlaintextMessages[i]);
            }

            for (int i = bobCiphertextMessages.Count / 2; i < bobCiphertextMessages.Count; i++)
            {
                byte[] receivedPlaintext = aliceCipher.Decrypt(new SignalMessage(bobCiphertextMessages[i].Serialize()));
                CollectionAssert.AreEqual(receivedPlaintext, bobPlaintextMessages[i]);
            }
        }
        private void InitializeSessionsV3(SessionState aliceSessionState, SessionState bobSessionState)
        {
            EcKeyPair aliceIdentityKeyPair = Curve.GenerateKeyPair();
            IdentityKeyPair aliceIdentityKey = new IdentityKeyPair(new IdentityKey(aliceIdentityKeyPair.GetPublicKey()),
                                                                   aliceIdentityKeyPair.GetPrivateKey());
            EcKeyPair aliceBaseKey = Curve.GenerateKeyPair();
            EcKeyPair aliceEphemeralKey = Curve.GenerateKeyPair();

            EcKeyPair alicePreKey = aliceBaseKey;

            EcKeyPair bobIdentityKeyPair = Curve.GenerateKeyPair();
            IdentityKeyPair bobIdentityKey = new IdentityKeyPair(new IdentityKey(bobIdentityKeyPair.GetPublicKey()),
                                                                 bobIdentityKeyPair.GetPrivateKey());
            EcKeyPair bobBaseKey = Curve.GenerateKeyPair();
            EcKeyPair bobEphemeralKey = bobBaseKey;

            EcKeyPair bobPreKey = Curve.GenerateKeyPair();

            AliceSignalProtocolParameters aliceParameters = AliceSignalProtocolParameters.NewBuilder()
                .SetOurBaseKey(aliceBaseKey)
                .SetOurIdentityKey(aliceIdentityKey)
                .SetTheirOneTimePreKey(May<IEcPublicKey>.NoValue)
                .SetTheirRatchetKey(bobEphemeralKey.GetPublicKey())
                .SetTheirSignedPreKey(bobBaseKey.GetPublicKey())
                .SetTheirIdentityKey(bobIdentityKey.GetPublicKey())
                .Create();

            BobSignalProtocolParameters bobParameters = BobSignalProtocolParameters.NewBuilder()
                .SetOurRatchetKey(bobEphemeralKey)
                .SetOurSignedPreKey(bobBaseKey)
                .SetOurOneTimePreKey(May<EcKeyPair>.NoValue)
                .SetOurIdentityKey(bobIdentityKey)
                .SetTheirIdentityKey(aliceIdentityKey.GetPublicKey())
                .SetTheirBaseKey(aliceBaseKey.GetPublicKey())
                .Create();

            RatchetingSession.InitializeSession(aliceSessionState, aliceParameters);
            RatchetingSession.InitializeSession(bobSessionState, bobParameters);
        }

        
    }
}
