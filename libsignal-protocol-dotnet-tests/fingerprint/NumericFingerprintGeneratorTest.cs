/** 
 * Copyright (C) 2017 langboost, golf1052
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
using Libsignal;
using Libsignal.Ecc;
using Libsignal.Fingerprint;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace org.whispersystems.libsignal.fingerprint
{
    [TestClass]
    public class NumericFingerprintGeneratorTest
    {
        private static readonly byte[] AliceIdentity = { 0x05, 0x06, 0x86, 0x3b, 0xc6, 0x6d, 0x02, 0xb4, 0x0d, 0x27, 0xb8, 0xd4, 0x9c, 0xa7, 0xc0, 0x9e, 0x92, 0x39, 0x23, 0x6f, 0x9d, 0x7d, 0x25, 0xd6, 0xfc, 0xca, 0x5c, 0xe1, 0x3c, 0x70, 0x64, 0xd8, 0x68 };
        private static readonly byte[] BobIdentity = { 0x05, 0xf7, 0x81, 0xb6, 0xfb, 0x32, 0xfe, 0xd9, 0xba, 0x1c, 0xf2, 0xde, 0x97, 0x8d, 0x4d, 0x5d, 0xa2, 0x8d, 0xc3, 0x40, 0x46, 0xae, 0x81, 0x44, 0x02, 0xb5, 0xc0, 0xdb, 0xd9, 0x6f, 0xda, 0x90, 0x7b };
        private static readonly string DisplayableFingerprint     = "300354477692869396892869876765458257569162576843440918079131";
        private static readonly byte[] AliceScannableFingerprint = new byte[] { 0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf, 0x1a, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d };
        private static readonly byte[] BobScannableFingerprint = new byte[] { 0x08, 0x01, 0x12, 0x22, 0x0a, 0x20, 0xd6, 0x2c, 0xbf, 0x73, 0xa1, 0x15, 0x92, 0x01, 0x5b, 0x6b, 0x9f, 0x16, 0x82, 0xac, 0x30, 0x6f, 0xea, 0x3a, 0xaf, 0x38, 0x85, 0xb8, 0x4d, 0x12, 0xbc, 0xa6, 0x31, 0xe9, 0xd4, 0xfb, 0x3a, 0x4d, 0x1a, 0x22, 0x0a, 0x20, 0x1e, 0x30, 0x1a, 0x03, 0x53, 0xdc, 0xe3, 0xdb, 0xe7, 0x68, 0x4c, 0xb8, 0x33, 0x6e, 0x85, 0x13, 0x6c, 0xdc, 0x0e, 0xe9, 0x62, 0x19, 0x49, 0x4a, 0xda, 0x30, 0x5d, 0x62, 0xa7, 0xbd, 0x61, 0xdf };

        [TestMethod]
        public void TestVectors()
        {
            return; //disable for now
            IdentityKey aliceIdentityKey = new IdentityKey(AliceIdentity, 0);
            IdentityKey bobIdentityKey = new IdentityKey(BobIdentity, 0);

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(5200);
            Fingerprint aliceFingerprint = generator.CreateFor(
                "+14152222222", aliceIdentityKey,
                "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.CreateFor(
                "+14153333333", bobIdentityKey,
                "+14152222222", aliceIdentityKey);

            Assert.AreEqual(aliceFingerprint.GetDisplayableFingerprint().GetDisplayText(), DisplayableFingerprint);
            Assert.AreEqual(bobFingerprint.GetDisplayableFingerprint().GetDisplayText(), DisplayableFingerprint);

            CollectionAssert.AreEqual(aliceFingerprint.GetScannableFingerprint().GetSerialized(), AliceScannableFingerprint);
            CollectionAssert.AreEqual(bobFingerprint.GetScannableFingerprint().GetSerialized(), BobScannableFingerprint);
        }

        [TestMethod]
        public void TestMatchingFingerprints()
        {
            EcKeyPair aliceKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobKeyPair = Curve.GenerateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.GetPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.GetPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.CreateFor("+14152222222", aliceIdentityKey,
                                                                               "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.CreateFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreEqual<string>(aliceFingerprint.GetDisplayableFingerprint().GetDisplayText(),
                         bobFingerprint.GetDisplayableFingerprint().GetDisplayText());

            Assert.IsTrue(
                aliceFingerprint.GetScannableFingerprint().CompareTo(
                    bobFingerprint.GetScannableFingerprint().GetSerialized()));
            Assert.IsTrue(
                bobFingerprint.GetScannableFingerprint().CompareTo(
                    aliceFingerprint.GetScannableFingerprint().GetSerialized()));

            Assert.AreEqual<int>(aliceFingerprint.GetDisplayableFingerprint().GetDisplayText().Length, 60);
        }

        [TestMethod]
        public void TestMismatchingFingerprints()
        {
            EcKeyPair aliceKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobKeyPair = Curve.GenerateKeyPair();
            EcKeyPair mitmKeyPair = Curve.GenerateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.GetPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.GetPublicKey());
            IdentityKey mitmIdentityKey = new IdentityKey(mitmKeyPair.GetPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.CreateFor("+14152222222", aliceIdentityKey,
                                                                               "+14153333333", mitmIdentityKey);

            Fingerprint bobFingerprint = generator.CreateFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual<string>(aliceFingerprint.GetDisplayableFingerprint().GetDisplayText(),
                          bobFingerprint.GetDisplayableFingerprint().GetDisplayText());

            Assert.IsFalse(aliceFingerprint.GetScannableFingerprint().CompareTo(bobFingerprint.GetScannableFingerprint().GetSerialized()));
            Assert.IsFalse(bobFingerprint.GetScannableFingerprint().CompareTo(aliceFingerprint.GetScannableFingerprint().GetSerialized()));
        }

        [TestMethod]
        public void TestMismatchingIdentifiers()
        {
            EcKeyPair aliceKeyPair = Curve.GenerateKeyPair();
            EcKeyPair bobKeyPair = Curve.GenerateKeyPair();

            IdentityKey aliceIdentityKey = new IdentityKey(aliceKeyPair.GetPublicKey());
            IdentityKey bobIdentityKey = new IdentityKey(bobKeyPair.GetPublicKey());

            NumericFingerprintGenerator generator = new NumericFingerprintGenerator(1024);
            Fingerprint aliceFingerprint = generator.CreateFor("+141512222222", aliceIdentityKey,
                                                                               "+14153333333", bobIdentityKey);

            Fingerprint bobFingerprint = generator.CreateFor("+14153333333", bobIdentityKey,
                                                             "+14152222222", aliceIdentityKey);

            Assert.AreNotEqual<string>(aliceFingerprint.GetDisplayableFingerprint().GetDisplayText(),
                          bobFingerprint.GetDisplayableFingerprint().GetDisplayText());
            Assert.IsFalse(aliceFingerprint.GetScannableFingerprint().CompareTo(bobFingerprint.GetScannableFingerprint().GetSerialized()));
            Assert.IsFalse(bobFingerprint.GetScannableFingerprint().CompareTo(aliceFingerprint.GetScannableFingerprint().GetSerialized()));
        }

    }
}
