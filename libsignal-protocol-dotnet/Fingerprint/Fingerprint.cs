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
 
 namespace Libsignal.Fingerprint
{
    public class Fingerprint
    {

        private readonly DisplayableFingerprint _displayableFingerprint;
        private readonly ScannableFingerprint _scannableFingerprint;

        public Fingerprint(DisplayableFingerprint displayableFingerprint,
                           ScannableFingerprint scannableFingerprint)
        {
            _displayableFingerprint = displayableFingerprint;
            _scannableFingerprint = scannableFingerprint;
        }

        /**
         * @return A text fingerprint that can be displayed and compared remotely.
         */
        public DisplayableFingerprint GetDisplayableFingerprint()
        {
            return _displayableFingerprint;
        }

        /**
         * @return A scannable fingerprint that can be scanned anc compared locally.
         */
        public ScannableFingerprint GetScannableFingerprint()
        {
            return _scannableFingerprint;
        }
    }
}