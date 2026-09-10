"""Unified analyzer candidate contract."""

from secval.candidates.contracts import (
    Candidate,
    CandidateKind,
    CandidateStatus,
    candidate_identity,
)

__all__ = ["Candidate", "CandidateKind", "CandidateStatus", "candidate_identity"]
