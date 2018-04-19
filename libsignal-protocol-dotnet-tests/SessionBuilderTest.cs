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

using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using Libsignal;
using Libsignal.Ecc;
using Libsignal.Protocol;
using Libsignal.State;
using Libsignal.Util;

namespace libsignal_test
{

    [TestClass]
    public class SessionBuilderTest
    {
        private static readonly SignalProtocolAddress AliceAddress = new SignalProtocolAddress("+14151111111", 1);
        private static readonly SignalProtocolAddress BobAddress = new SignalProtocolAddress("+14152222222", 1);

        class BobDecryptionCallback : IDecryptionCallback
        {
            readonly ISignalProtocolStore _bobStore;
            readonly String _originalMessage;

            public BobDecryptionCallback(ISignalProtocolStore bobStore, String originalMessage)
            {
                this._bobStore = bobStore;
                this._originalMessage = originalMessage;
            }

            public void HandlePlaintext(byte[] plaintext)
            {
                Assert.AreEqual(_originalMessage, Encoding.UTF8.GetString(plaintext));
                Assert.IsFalse(_bobStore.ContainsSession(AliceAddress));
            }
        }

        [TestMethod, TestCategory("libsignal")]
        public void TestBasicPreKeyV3()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);

            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();
            EcKeyPair bobPreKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobSignedPreKeyPair = Curve.GenerateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                             bobSignedPreKeyPair.GetPublicKey().Serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.GetPublicKey(),
                                                      22, bobSignedPreKeyPair.GetPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().GetPublicKey());

            aliceSessionBuilder.Process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BobAddress));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            CiphertextMessage outgoingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PrekeyType, outgoingMessage.GetMessageType());

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.Serialize());
            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.GetPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.CurrentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);
            byte[] plaintext = bobSessionCipher.Decrypt(incomingMessage, new BobDecryptionCallback(bobStore, originalMessage));

            Assert.IsTrue(bobStore.ContainsSession(AliceAddress));
            Assert.AreEqual((uint)3, bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(AliceAddress).GetSessionState().GetAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));
            Assert.AreEqual(CiphertextMessage.WhisperType, bobOutgoingMessage.GetMessageType());

            byte[] alicePlaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobOutgoingMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            RunInteraction(aliceStore, bobStore);

            aliceStore = new TestInMemorySignalProtocolStore();
            aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);
            aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);

            bobPreKeyPair = Curve.GenerateKeyPair();
            bobSignedPreKeyPair = Curve.GenerateKeyPair();
            bobSignedPreKeySignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(), bobSignedPreKeyPair.GetPublicKey().Serialize());
            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(),
                                         1, 31338, bobPreKeyPair.GetPublicKey(),
                                         23, bobSignedPreKeyPair.GetPublicKey(), bobSignedPreKeySignature,
                                         bobStore.GetIdentityKeyPair().GetPublicKey());

            bobStore.StorePreKey(31338, new PreKeyRecord(bobPreKey.GetPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(23, new SignedPreKeyRecord(23, DateUtil.CurrentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));
            aliceSessionBuilder.Process(bobPreKey);

            outgoingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            try
            {
                plaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(outgoingMessage.Serialize()));
                throw new Exception("shouldn't be trusted!");
            }
            catch (UntrustedIdentityException)
            {
                bobStore.SaveIdentity(AliceAddress, new PreKeySignalMessage(outgoingMessage.Serialize()).GetIdentityKey());
            }

            plaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(outgoingMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                         31337, Curve.GenerateKeyPair().GetPublicKey(),
                                         23, bobSignedPreKeyPair.GetPublicKey(), bobSignedPreKeySignature,
                                         aliceStore.GetIdentityKeyPair().GetPublicKey());

            try
            {
                aliceSessionBuilder.Process(bobPreKey);
                throw new Exception("shoulnd't be trusted!");
            }
            catch (UntrustedIdentityException)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libsignal")]
        public void TestBadSignedPreKeySignature()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);

            IDentityKeyStore bobIdentityKeyStore = new TestInMemoryIdentityKeyStore();

            EcKeyPair bobPreKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobSignedPreKeyPair = Curve.GenerateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.CalculateSignature(bobIdentityKeyStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                          bobSignedPreKeyPair.GetPublicKey().Serialize());


            for (int i = 0; i < bobSignedPreKeySignature.Length * 8; i++)
            {
                byte[] modifiedSignature = new byte[bobSignedPreKeySignature.Length];
                Array.Copy(bobSignedPreKeySignature, 0, modifiedSignature, 0, modifiedSignature.Length);

                modifiedSignature[i / 8] ^= (byte)(0x01 << (i % 8));

                PreKeyBundle bobPreKey = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                          31337, bobPreKeyPair.GetPublicKey(),
                                                          22, bobSignedPreKeyPair.GetPublicKey(), modifiedSignature,
                                                          bobIdentityKeyStore.GetIdentityKeyPair().GetPublicKey());
                
                try
                {
                    aliceSessionBuilder.Process(bobPreKey);
                    throw new Exception("Accepted modified device key signature!");
                }
                catch (InvalidKeyException)
                {
                    // good
                }
            }

            PreKeyBundle bobPreKey2 = new PreKeyBundle(bobIdentityKeyStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.GetPublicKey(),
                                                      22, bobSignedPreKeyPair.GetPublicKey(), bobSignedPreKeySignature,
                                                      bobIdentityKeyStore.GetIdentityKeyPair().GetPublicKey());

            aliceSessionBuilder.Process(bobPreKey2);
        }

        [TestMethod, TestCategory("libsignal")]
        public void TestRepeatBundleMessageV3()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);

            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            EcKeyPair bobPreKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobSignedPreKeyPair = Curve.GenerateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                          bobSignedPreKeyPair.GetPublicKey().Serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.GetPublicKey(),
                                                      22, bobSignedPreKeyPair.GetPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().GetPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.GetPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.CurrentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.Process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));
            CiphertextMessage outgoingMessageTwo = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PrekeyType, outgoingMessageOne.GetMessageType());
            Assert.AreEqual(CiphertextMessage.PrekeyType, outgoingMessageTwo.GetMessageType());

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessageOne.Serialize());

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            byte[] plaintext = bobSessionCipher.Decrypt(incomingMessage);
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobOutgoingMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            byte[] alicePlaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobOutgoingMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

            // The test

            PreKeySignalMessage incomingMessageTwo = new PreKeySignalMessage(outgoingMessageTwo.Serialize());

            plaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(incomingMessageTwo.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            bobOutgoingMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));
            alicePlaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobOutgoingMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(alicePlaintext));

        }

        [TestMethod, TestCategory("libsignal")]
        public void TestBadMessageBundle()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);

            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            EcKeyPair bobPreKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobSignedPreKeyPair = Curve.GenerateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                          bobSignedPreKeyPair.GetPublicKey().Serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      31337, bobPreKeyPair.GetPublicKey(),
                                                      22, bobSignedPreKeyPair.GetPublicKey(), bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().GetPublicKey());

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.GetPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.CurrentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            aliceSessionBuilder.Process(bobPreKey);

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            CiphertextMessage outgoingMessageOne = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.PrekeyType, outgoingMessageOne.GetMessageType());

            byte[] goodMessage = outgoingMessageOne.Serialize();
            byte[] badMessage = new byte[goodMessage.Length];
            Array.Copy(goodMessage, 0, badMessage, 0, badMessage.Length);

            badMessage[badMessage.Length - 10] ^= 0x01;

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(badMessage);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            byte[] plaintext = new byte[0];

            try
            {
                plaintext = bobSessionCipher.Decrypt(incomingMessage);
                throw new Exception("Decrypt should have failed!");
            }
            catch (InvalidMessageException)
            {
                // good.
            }

            Assert.IsTrue(bobStore.ContainsPreKey(31337));

            plaintext = bobSessionCipher.Decrypt(new PreKeySignalMessage(goodMessage));

            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
            Assert.IsFalse(bobStore.ContainsPreKey(31337));
        }

        [TestMethod, TestCategory("libsignal")]
        public void TestOptionalOneTimePreKey()
        {
            ISignalProtocolStore aliceStore = new TestInMemorySignalProtocolStore();
            SessionBuilder aliceSessionBuilder = new SessionBuilder(aliceStore, BobAddress);

            ISignalProtocolStore bobStore = new TestInMemorySignalProtocolStore();

            EcKeyPair bobPreKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobSignedPreKeyPair = Curve.GenerateKeyPair();
            byte[] bobSignedPreKeySignature = Curve.CalculateSignature(bobStore.GetIdentityKeyPair().GetPrivateKey(),
                                                                          bobSignedPreKeyPair.GetPublicKey().Serialize());

            PreKeyBundle bobPreKey = new PreKeyBundle(bobStore.GetLocalRegistrationId(), 1,
                                                      0, null,
                                                      22, bobSignedPreKeyPair.GetPublicKey(),
                                                      bobSignedPreKeySignature,
                                                      bobStore.GetIdentityKeyPair().GetPublicKey());

            aliceSessionBuilder.Process(bobPreKey);

            Assert.IsTrue(aliceStore.ContainsSession(BobAddress));
            Assert.AreEqual((uint)3, aliceStore.LoadSession(BobAddress).GetSessionState().GetSessionVersion());

            String originalMessage = "L'homme est condamné à être libre";
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            CiphertextMessage outgoingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(outgoingMessage.GetMessageType(), CiphertextMessage.PrekeyType);

            PreKeySignalMessage incomingMessage = new PreKeySignalMessage(outgoingMessage.Serialize());
            Assert.IsFalse(incomingMessage.GetPreKeyId().HasValue);

            bobStore.StorePreKey(31337, new PreKeyRecord(bobPreKey.GetPreKeyId(), bobPreKeyPair));
            bobStore.StoreSignedPreKey(22, new SignedPreKeyRecord(22, DateUtil.CurrentTimeMillis(), bobSignedPreKeyPair, bobSignedPreKeySignature));

            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);
            byte[] plaintext = bobSessionCipher.Decrypt(incomingMessage);

            Assert.IsTrue(bobStore.ContainsSession(AliceAddress));
            Assert.AreEqual((uint)3, bobStore.LoadSession(AliceAddress).GetSessionState().GetSessionVersion());
            Assert.IsNotNull(bobStore.LoadSession(AliceAddress).GetSessionState().GetAliceBaseKey());
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));
        }

        private void RunInteraction(ISignalProtocolStore aliceStore, ISignalProtocolStore bobStore)
        {
            SessionCipher aliceSessionCipher = new SessionCipher(aliceStore, BobAddress);
            SessionCipher bobSessionCipher = new SessionCipher(bobStore, AliceAddress);

            String originalMessage = "smert ze smert";
            CiphertextMessage aliceMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WhisperType, aliceMessage.GetMessageType());

            byte[] plaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            CiphertextMessage bobMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(originalMessage));

            Assert.AreEqual(CiphertextMessage.WhisperType, bobMessage.GetMessageType());

            plaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobMessage.Serialize()));
            Assert.AreEqual(originalMessage, Encoding.UTF8.GetString(plaintext));

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceLoopingMessage.Serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobLoopingMessage.Serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            HashSet<Pair<String, CiphertextMessage>> aliceOutOfOrderMessages = new HashSet<Pair<String, CiphertextMessage>>();

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                aliceOutOfOrderMessages.Add(new Pair<String, CiphertextMessage>(loopingMessage, aliceLoopingMessage));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("What do we mean by saying that existence precedes essence? " +
                                         "We mean that man first of all exists, encounters himself, " +
                                         "surges up in the world--and defines himself aftward. " + i);
                CiphertextMessage aliceLoopingMessage = aliceSessionCipher.Encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceLoopingMessage.Serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            for (int i = 0; i < 10; i++)
            {
                String loopingMessage = ("You can only desire based on what you know: " + i);
                CiphertextMessage bobLoopingMessage = bobSessionCipher.Encrypt(Encoding.UTF8.GetBytes(loopingMessage));

                byte[] loopingPlaintext = aliceSessionCipher.Decrypt(new SignalMessage(bobLoopingMessage.Serialize()));
                Assert.AreEqual(loopingMessage, Encoding.UTF8.GetString(loopingPlaintext));
            }

            foreach (Pair<String, CiphertextMessage> aliceOutOfOrderMessage in aliceOutOfOrderMessages)
            {
                byte[] outOfOrderPlaintext = bobSessionCipher.Decrypt(new SignalMessage(aliceOutOfOrderMessage.Second().Serialize()));
                Assert.AreEqual(aliceOutOfOrderMessage.First(), Encoding.UTF8.GetString(outOfOrderPlaintext));
            }
        }
    }
}
