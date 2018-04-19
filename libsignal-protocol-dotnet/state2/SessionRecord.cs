﻿using Google.Protobuf;
using System.Collections.Generic;
using System.Linq;

namespace libsignal.state
{
    /// <summary>
    /// A SessionRecord encapsulates the state of an ongoing session.</summary>
    public class SessionRecord
    {
        private static int _archivedStatesMaxLength = 40;

        private SessionState _sessionState = new SessionState();
        private LinkedList<SessionState> _previousStates = new LinkedList<SessionState>();
        private bool _fresh = false;

        public SessionRecord()
        {
            this._fresh = true;
        }

        public SessionRecord(SessionState sessionState)
        {
            this._sessionState = sessionState;
            this._fresh = false;
        }

        public SessionRecord(byte[] serialized)
        {
            RecordStructure record = RecordStructure.Parser.ParseFrom(serialized);
            this._sessionState = new SessionState(record.CurrentSession);
            this._fresh = false;

            foreach (SessionStructure previousStructure in record.PreviousSessions)
            {
                _previousStates.AddLast(new SessionState(previousStructure)); // add -> AddLast (java)
            }
        }

        public bool HasSessionState(uint version, byte[] aliceBaseKey)
        {
            if (_sessionState.GetSessionVersion() == version && Enumerable.SequenceEqual(aliceBaseKey, _sessionState.GetAliceBaseKey()))
            {
                return true;
            }
            foreach (SessionState state in _previousStates)
            {
                if (state.GetSessionVersion() == version && Enumerable.SequenceEqual(aliceBaseKey, state.GetAliceBaseKey()))
                {
                    return true;
                }
            }
            return false;
        }

        public SessionState GetSessionState()
        {
            return _sessionState;
        }

        /// <returns>
        /// return the list of all currently maintained "previous" session states.</returns>
        public LinkedList<SessionState> GetPreviousSessionStates()
        {
            return _previousStates;
        }

        public void RemovePreviousSessionStates()
        {
            _previousStates.Clear();
        }

        public bool IsFresh()
        {
            return _fresh;
        }

         /// <summary>
         /// Move the current SessionState into the list of "previous" session states,
         /// and replace the current SessionState with a fresh reset instance.</summary>
        public void ArchiveCurrentState()
        {
            PromoteState(new SessionState());
        }

        public void PromoteState(SessionState promotedState)
        {
            this._previousStates.AddFirst(_sessionState);
            this._sessionState = promotedState;
            if (_previousStates.Count > _archivedStatesMaxLength)
            {
                _previousStates.RemoveLast();
            }
        }

        public void SetState(SessionState sessionState)
        {
            this._sessionState = sessionState;
        }

        /// <returns>
        /// Returns a serialized version of the current SessionRecord.</returns>
        public byte[] Serialize()
        {
            List<SessionStructure> previousStructures = new List<SessionStructure>();
            foreach (SessionState previousState in _previousStates)
            {
                previousStructures.Add(previousState.GetStructure());
            }
            RecordStructure record = new RecordStructure
            {
                CurrentSession = _sessionState.GetStructure(),
            };
            record.PreviousSessions.AddRange(previousStructures);
            return record.ToByteArray();
        }
    }
}
