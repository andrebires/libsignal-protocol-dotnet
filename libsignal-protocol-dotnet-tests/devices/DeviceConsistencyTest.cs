/** 
 * Copyright (C) 2017 golf1052
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
using libsignal;
using libsignal.devices;
using libsignal.protocol;
using libsignal.util;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace signal_protocol_tests.devices
{
    [TestClass]
    public class DeviceConsistencyTest
    {
        [TestMethod]
        public void TestDeviceConsistency()
        {
            IdentityKeyPair deviceOne = KeyHelper.GenerateIdentityKeyPair();
            IdentityKeyPair deviceTwo = KeyHelper.GenerateIdentityKeyPair();
            IdentityKeyPair deviceThree = KeyHelper.GenerateIdentityKeyPair();

            List<IdentityKey> keyList = new List<IdentityKey>(new[]
            {
                deviceOne.GetPublicKey(),
                deviceTwo.GetPublicKey(),
                deviceThree.GetPublicKey()
            });

            Random random = new Random();

            HelperMethods.Shuffle(keyList, random);
            DeviceConsistencyCommitment deviceOneCommitment = new DeviceConsistencyCommitment(1, keyList);

            HelperMethods.Shuffle(keyList, random);
            DeviceConsistencyCommitment deviceTwoCommitment = new DeviceConsistencyCommitment(1, keyList);

            HelperMethods.Shuffle(keyList, random);
            DeviceConsistencyCommitment deviceThreeCommitment = new DeviceConsistencyCommitment(1, keyList);

            CollectionAssert.AreEqual(deviceOneCommitment.ToByteArray(), deviceTwoCommitment.ToByteArray());
            CollectionAssert.AreEqual(deviceTwoCommitment.ToByteArray(), deviceThreeCommitment.ToByteArray());

            DeviceConsistencyMessage deviceOneMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceOne);
            DeviceConsistencyMessage deviceTwoMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceTwo);
            DeviceConsistencyMessage deviceThreeMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceThree);

            DeviceConsistencyMessage receivedDeviceOneMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceOneMessage.GetSerialized(), deviceOne.GetPublicKey());
            DeviceConsistencyMessage receivedDeviceTwoMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceTwoMessage.GetSerialized(), deviceTwo.GetPublicKey());
            DeviceConsistencyMessage receivedDeviceThreeMessage = new DeviceConsistencyMessage(deviceOneCommitment, deviceThreeMessage.GetSerialized(), deviceThree.GetPublicKey());

            CollectionAssert.AreEqual(deviceOneMessage.GetSignature().GetVrfOutput(), receivedDeviceOneMessage.GetSignature().GetVrfOutput());
            CollectionAssert.AreEqual(deviceTwoMessage.GetSignature().GetVrfOutput(), receivedDeviceTwoMessage.GetSignature().GetVrfOutput());
            CollectionAssert.AreEqual(deviceThreeMessage.GetSignature().GetVrfOutput(), receivedDeviceThreeMessage.GetSignature().GetVrfOutput());

            string codeOne = GenerateCode(deviceOneCommitment, deviceOneMessage, receivedDeviceTwoMessage, receivedDeviceThreeMessage);
            string codeTwo = GenerateCode(deviceTwoCommitment, deviceTwoMessage, receivedDeviceThreeMessage, receivedDeviceOneMessage);
            string codeThree = GenerateCode(deviceThreeCommitment, deviceThreeMessage, receivedDeviceTwoMessage, receivedDeviceOneMessage);

            Assert.AreEqual(codeOne, codeTwo);
            Assert.AreEqual(codeTwo, codeThree);
        }

        private string GenerateCode(DeviceConsistencyCommitment commitment, params DeviceConsistencyMessage[] messages)
        {
            List<DeviceConsistencySignature> signatures = new List<DeviceConsistencySignature>();
            foreach (DeviceConsistencyMessage message in messages)
            {
                signatures.Add(message.GetSignature());
            }

            return DeviceConsistencyCodeGenerator.GenerateFor(commitment, signatures);
        }
    }
}
