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
using libsignal.groups;
using libsignal.protocol;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace libsignal_test.groups
{
    [TestClass]
    public class GroupCipherTest
    {
        private static readonly SignalProtocolAddress SenderAddress = new SignalProtocolAddress("+14150001111", 1);
        private static readonly SenderKeyName GroupSender = new SenderKeyName("nihilist history reading group", SenderAddress);

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestNoSession()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GroupSender);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GroupSender);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.Create(GroupSender);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.Serialize());

            //    bobSessionBuilder.process(GROUP_SENDER, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            try
            {
                byte[] plaintextFromAlice = bobGroupCipher.Decrypt(ciphertextFromAlice);
                throw new Exception("Should be no session!");
            }
            catch (NoSessionException)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestBasicEncryptDecrypt()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GroupSender);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GroupSender);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.Create(GroupSender);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.Serialize());
            bobSessionBuilder.Process(GroupSender, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            byte[] plaintextFromAlice = bobGroupCipher.Decrypt(ciphertextFromAlice);

            Assert.AreEqual("smert ze smert", Encoding.UTF8.GetString(plaintextFromAlice));
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestLargeMessages()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, GroupSender);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, GroupSender);

            SenderKeyDistributionMessage sentAliceDistributionMessage = aliceSessionBuilder.Create(GroupSender);
            SenderKeyDistributionMessage receivedAliceDistributionMessage = new SenderKeyDistributionMessage(sentAliceDistributionMessage.Serialize());
            bobSessionBuilder.Process(GroupSender, receivedAliceDistributionMessage);

            byte[] plaintext = new byte[1024 * 1024];
            new Random().NextBytes(plaintext);

            byte[] ciphertextFromAlice = aliceGroupCipher.Encrypt(plaintext);
            byte[] plaintextFromAlice = bobGroupCipher.Decrypt(ciphertextFromAlice);

            CollectionAssert.AreEqual(plaintext, plaintextFromAlice);
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestBasicRatchet()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GroupSender;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage sentAliceDistributionMessage =
                aliceSessionBuilder.Create(aliceName);
            SenderKeyDistributionMessage receivedAliceDistributionMessage =
                new SenderKeyDistributionMessage(sentAliceDistributionMessage.Serialize());

            bobSessionBuilder.Process(aliceName, receivedAliceDistributionMessage);

            byte[] ciphertextFromAlice = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("smert ze smert"));
            byte[] ciphertextFromAlice2 = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("smert ze smert2"));
            byte[] ciphertextFromAlice3 = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("smert ze smert3"));

            byte[] plaintextFromAlice = bobGroupCipher.Decrypt(ciphertextFromAlice);

            try
            {
                bobGroupCipher.Decrypt(ciphertextFromAlice);
                throw new Exception("Should have ratcheted forward!");
            }
            catch (DuplicateMessageException)
            {
                // good
            }

            byte[] plaintextFromAlice2 = bobGroupCipher.Decrypt(ciphertextFromAlice2);
            byte[] plaintextFromAlice3 = bobGroupCipher.Decrypt(ciphertextFromAlice3);

            Assert.AreEqual("smert ze smert", Encoding.UTF8.GetString(plaintextFromAlice));
            Assert.AreEqual("smert ze smert2", Encoding.UTF8.GetString(plaintextFromAlice2));
            Assert.AreEqual("smert ze smert3", Encoding.UTF8.GetString(plaintextFromAlice3));
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestLateJoin()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);


            SenderKeyName aliceName = GroupSender;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);


            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.Create(aliceName);
            // Send off to some people.

            for (int i = 0; i < 100; i++)
            {
                aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("up the punks up the punks up the punks"));
            }

            // Now Bob Joins.
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);


            SenderKeyDistributionMessage distributionMessageToBob = aliceSessionBuilder.Create(aliceName);
            bobSessionBuilder.Process(aliceName, new SenderKeyDistributionMessage(distributionMessageToBob.Serialize()));

            byte[] ciphertext = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("welcome to the group"));
            byte[] plaintext = bobGroupCipher.Decrypt(ciphertext);

            Assert.AreEqual("welcome to the group", Encoding.UTF8.GetString(plaintext));
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestOutOfOrder()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GroupSender;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage =
                aliceSessionBuilder.Create(aliceName);

            bobSessionBuilder.Process(aliceName, aliceDistributionMessage);

            List<byte[]> ciphertexts = new List<byte[]>(100);

            for (int i = 0; i < 100; i++)
            {
                ciphertexts.Add(aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("up the punks")));
            }

            while (ciphertexts.Count > 0)
            {
                int index = (int)(RandomUInt() % ciphertexts.Count);
                byte[] ciphertext = ciphertexts[index];
                ciphertexts.RemoveAt(index);
                byte[] plaintext = bobGroupCipher.Decrypt(ciphertext);

                Assert.AreEqual("up the punks", Encoding.UTF8.GetString(plaintext));
            }
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestEncryptNoSession()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, new SenderKeyName("coolio groupio", new SignalProtocolAddress("+10002223333", 1)));
            try
            {
                aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("up the punks"));
                throw new Exception("Should have failed!");
            }
            catch (NoSessionException)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestTooFarInFuture()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GroupSender;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.Create(aliceName);

            bobSessionBuilder.Process(aliceName, aliceDistributionMessage);

            for (int i = 0; i < 2001; i++)
            {
                aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("up the punks"));
            }

            byte[] tooFarCiphertext = aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("notta gonna worka"));
            try
            {
                bobGroupCipher.Decrypt(tooFarCiphertext);
                throw new Exception("Should have failed!");
            }
            catch (InvalidMessageException)
            {
                // good
            }
        }

        [TestMethod, TestCategory("libsignal.groups")]
        public void TestMessageKeyLimit()
        {
            InMemorySenderKeyStore aliceStore = new InMemorySenderKeyStore();
            InMemorySenderKeyStore bobStore = new InMemorySenderKeyStore();

            GroupSessionBuilder aliceSessionBuilder = new GroupSessionBuilder(aliceStore);
            GroupSessionBuilder bobSessionBuilder = new GroupSessionBuilder(bobStore);

            SenderKeyName aliceName = GroupSender;

            GroupCipher aliceGroupCipher = new GroupCipher(aliceStore, aliceName);
            GroupCipher bobGroupCipher = new GroupCipher(bobStore, aliceName);

            SenderKeyDistributionMessage aliceDistributionMessage = aliceSessionBuilder.Create(aliceName);

            bobSessionBuilder.Process(aliceName, aliceDistributionMessage);

            List<byte[]> inflight = new List<byte[]>();

            for (int i = 0; i < 2010; i++)
            {
                inflight.Add(aliceGroupCipher.Encrypt(Encoding.UTF8.GetBytes("up the punks")));
            }

            bobGroupCipher.Decrypt(inflight[1000]);
            bobGroupCipher.Decrypt(inflight[inflight.Count - 1]);

            try
            {
                bobGroupCipher.Decrypt(inflight[0]);
                throw new Exception("Should have failed!");
            }
            catch (DuplicateMessageException)
            {
                // good
            }
        }

        private uint RandomUInt()
        {

            byte[] randomBytes = new byte[4];
            using (var gen = RandomNumberGenerator.Create())
            {
                gen.GetBytes(randomBytes);
            }
            return BitConverter.ToUInt32(randomBytes, 0);
        }
    }
}
