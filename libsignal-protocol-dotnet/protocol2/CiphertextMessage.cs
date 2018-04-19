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

namespace libsignal.protocol
{
    public abstract class CiphertextMessage
    {

        public const uint CurrentVersion = 3;

        public const uint WhisperType = 2;
        public const uint PrekeyType = 3;
        public const uint SenderkeyType = 4;
        public const uint SenderkeyDistributionType = 5;

        /// <summary>
        /// This should be the worst case (worse than V2).  So not always accurate, but good enough for padding.
        /// </summary>
        public const uint EncryptedMessageOverhead = 53;

        public abstract byte[] Serialize();
        public abstract uint GetMessageType();

    }
}
