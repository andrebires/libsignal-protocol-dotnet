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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using libsignal;
using libsignal.util;

namespace org.whispersystems.libsignal.fingerprint
{
    public class DisplayableFingerprint
    {
        private readonly string _localFingerprintNumbers;
        private readonly string _remoteFingerprintNumbers;

        internal DisplayableFingerprint(byte[] localFingerprint, byte[] remoteFingerprint)
        {
            this._localFingerprintNumbers = GetDisplayStringFor(localFingerprint);
            this._remoteFingerprintNumbers = GetDisplayStringFor(remoteFingerprint);
        }

        public string GetDisplayText()
        {
            if (_localFingerprintNumbers.CompareTo(_remoteFingerprintNumbers) <= 0)
            {
                return _localFingerprintNumbers + _remoteFingerprintNumbers;
            }
            else
            {
                return _remoteFingerprintNumbers + _localFingerprintNumbers;
            }
        }

        private string GetDisplayStringFor(byte[] fingerprint)
        {
            return GetEncodedChunk(fingerprint, 0) +
                GetEncodedChunk(fingerprint, 5) +
                GetEncodedChunk(fingerprint, 10) +
                GetEncodedChunk(fingerprint, 15) +
                GetEncodedChunk(fingerprint, 20) +
                GetEncodedChunk(fingerprint, 25);
        }

        private string GetEncodedChunk(byte[] hash, int offset)
        {
            long chunk = ByteUtil.ByteArray5ToLong(hash, offset) % 100000;
            return string.Format("{0:d5}", chunk);
        }
    }
}