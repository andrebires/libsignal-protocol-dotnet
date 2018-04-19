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

namespace Libsignal.Fingerprint
{
    public class FingerprintIdentifierMismatchException : Exception
    {

        private readonly string _localIdentifier;
        private readonly string _remoteIdentifier;
        private readonly string _scannedLocalIdentifier;
        private readonly string _scannedRemoteIdentifier;

        public FingerprintIdentifierMismatchException(string localIdentifier, string remoteIdentifier,
                                                      string scannedLocalIdentifier, string scannedRemoteIdentifier)
        {
            _localIdentifier = localIdentifier;
            _remoteIdentifier = remoteIdentifier;
            _scannedLocalIdentifier = scannedLocalIdentifier;
            _scannedRemoteIdentifier = scannedRemoteIdentifier;
        }

        public string GetScannedRemoteIdentifier()
        {
            return _scannedRemoteIdentifier;
        }

        public string GetScannedLocalIdentifier()
        {
            return _scannedLocalIdentifier;
        }

        public string GetRemoteIdentifier()
        {
            return _remoteIdentifier;
        }

        public string GetLocalIdentifier()
        {
            return _localIdentifier;
        }
    }
}