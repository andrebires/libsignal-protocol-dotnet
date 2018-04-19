/** 
 * Copyright (C) 2017 smndtrl, langboost, golf1052
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


using Google.Protobuf;
using Libsignal.Util;

namespace Libsignal.Fingerprint
{

    public class ScannableFingerprint
    {
        private static readonly int Version = 0;

        private readonly CombinedFingerprints _fingerprints;

        internal ScannableFingerprint(byte[] localFingerprintData, byte[] remoteFingerprintData)
        {
            LogicalFingerprint localFingerprint = new LogicalFingerprint
            {
                Content = ByteString.CopyFrom(ByteUtil.Trim(localFingerprintData, 32))
            };

            LogicalFingerprint remoteFingerprint = new LogicalFingerprint
            {
                Content = ByteString.CopyFrom(ByteUtil.Trim(remoteFingerprintData, 32))
            };

            this._fingerprints = new CombinedFingerprints
            {
                Version = (uint)Version,
                LocalFingerprint = localFingerprint,
                RemoteFingerprint = remoteFingerprint
            };
        }

        /**
         * @return A byte string to be displayed in a QR code.
         */
        public byte[] GetSerialized()
        {
            return _fingerprints.ToByteArray();
        }

        /**
         * Compare a scanned QR code with what we expect.
         *
         * @param scannedFingerprintData The scanned data
         * @return True if matching, otehrwise false.
         * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
         * @throws FingerprintIdentifierMismatchException if the scanned fingerprint is for the wrong stable identifier.
         */
        public bool CompareTo(byte[] scannedFingerprintData)
        /* throws FingerprintVersionMismatchException,
               FingerprintIdentifierMismatchException,
               FingerprintParsingException */
        {
            try
            {
                CombinedFingerprints scanned = CombinedFingerprints.Parser.ParseFrom(scannedFingerprintData);

                if (scanned.RemoteFingerprintOneofCase == CombinedFingerprints.RemoteFingerprintOneofOneofCase.None ||
                    scanned.LocalFingerprintOneofCase == CombinedFingerprints.LocalFingerprintOneofOneofCase.None ||
                    scanned.VersionOneofCase == CombinedFingerprints.VersionOneofOneofCase.None ||
                    scanned.Version != _fingerprints.Version)
                {
                    throw new FingerprintVersionMismatchException((int)scanned.Version, Version);
                }

                return ByteUtil.IsEqual(_fingerprints.LocalFingerprint.Content.ToByteArray(), scanned.RemoteFingerprint.Content.ToByteArray()) &&
                       ByteUtil.IsEqual(_fingerprints.RemoteFingerprint.Content.ToByteArray(), scanned.LocalFingerprint.Content.ToByteArray());
            }
            catch (InvalidProtocolBufferException e)
            {
                throw new FingerprintParsingException(e);
            }
        }
    }
}
